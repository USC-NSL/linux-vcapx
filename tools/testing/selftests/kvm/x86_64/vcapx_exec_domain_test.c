// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "apic.h"
#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"

static uint64_t fuzz_state = 0x8d26f31b9c47a5e1ULL;

static void signal_handler(int signal);
static int create_executor(int domain_fd, uint64_t cookie,
			   uint64_t *generation);

static uint64_t fuzz_next(void)
{
	fuzz_state ^= fuzz_state << 13;
	fuzz_state ^= fuzz_state >> 7;
	fuzz_state ^= fuzz_state << 17;
	return fuzz_state;
}

static int create_domain_with_features(int kvm_fd, uint32_t max_capsules,
				       uint32_t max_executors,
				       uint64_t features,
				       uint64_t *generation)
{
	struct kvm_exec_domain_create create = {
		.size = sizeof(create),
		.max_capsules = max_capsules,
		.max_executors = max_executors,
		.requested_features = features,
	};
	int domain_fd;

	domain_fd = ioctl(kvm_fd, KVM_CREATE_EXEC_DOMAIN, &create);
	TEST_ASSERT(domain_fd >= 0,
		    KVM_IOCTL_ERROR(KVM_CREATE_EXEC_DOMAIN, domain_fd));
	TEST_ASSERT_EQ(create.negotiated_features, features);
	TEST_ASSERT(create.domain_generation != 0,
		    "KVM returned a zero execution-domain generation");
	*generation = create.domain_generation;
	return domain_fd;
}

static int create_domain(int kvm_fd, uint32_t max_capsules,
			 uint32_t max_executors, uint64_t *generation)
{
	return create_domain_with_features(kvm_fd, max_capsules, max_executors,
					   KVM_EXEC_FEATURE_BASE_OBJECTS,
					   generation);
}

static void assert_ioctl_errno(int fd, unsigned long request, void *arg,
			       int expected_errno)
{
	int ret;

	errno = 0;
	ret = ioctl(fd, request, arg);
	TEST_ASSERT(ret == -1 && errno == expected_errno,
		    "ioctl 0x%lx returned %d errno %d, expected errno %d",
		    request, ret, errno, expected_errno);
}

static void test_cross_vm_feature_dependencies(int kvm_fd)
{
	const uint64_t complete_features = KVM_EXEC_FEATURE_BASE_OBJECTS |
					   KVM_EXEC_FEATURE_INTRA_VM_CHAIN |
					   KVM_EXEC_FEATURE_CROSS_VM_CHAIN;
	struct kvm_exec_domain_create create = {
		.size = sizeof(create),
		.max_capsules = 2,
		.max_executors = 1,
	};
	int domain_fd;

	create.requested_features = KVM_EXEC_FEATURE_CROSS_VM_CHAIN;
	assert_ioctl_errno(kvm_fd, KVM_CREATE_EXEC_DOMAIN, &create, EINVAL);
	create.requested_features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				    KVM_EXEC_FEATURE_CROSS_VM_CHAIN;
	assert_ioctl_errno(kvm_fd, KVM_CREATE_EXEC_DOMAIN, &create, EINVAL);
	create.requested_features = KVM_EXEC_FEATURE_INTRA_VM_CHAIN |
				    KVM_EXEC_FEATURE_CROSS_VM_CHAIN;
	assert_ioctl_errno(kvm_fd, KVM_CREATE_EXEC_DOMAIN, &create, EINVAL);
	create.requested_features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				    KVM_EXEC_FEATURE_SYNC_EXITS;
	assert_ioctl_errno(kvm_fd, KVM_CREATE_EXEC_DOMAIN, &create, EINVAL);

	create.requested_features = complete_features;
	domain_fd = ioctl(kvm_fd, KVM_CREATE_EXEC_DOMAIN, &create);
	TEST_ASSERT(domain_fd >= 0,
		    KVM_IOCTL_ERROR(KVM_CREATE_EXEC_DOMAIN, domain_fd));
	TEST_ASSERT_EQ(create.negotiated_features, complete_features);
	close(domain_fd);
}

static void test_dynamic_dispatch_uapi_layout(void)
{
	TEST_ASSERT_EQ(sizeof(struct kvm_exec_dispatch_header), 256);
	TEST_ASSERT_EQ(sizeof(struct kvm_exec_command), 96);
	TEST_ASSERT_EQ(sizeof(struct kvm_exec_completion), 112);
	TEST_ASSERT_EQ(sizeof(struct kvm_exec_run_dispatch), 104);
	TEST_ASSERT_EQ(sizeof(struct kvm_exec_kick), 48);
	TEST_ASSERT_EQ(sizeof(struct kvm_exec_cancel), 56);
	TEST_ASSERT_EQ(KVM_EXEC_DISPATCH_COMMAND_OFFSET, 256);
	TEST_ASSERT_EQ(KVM_EXEC_DISPATCH_COMPLETION_OFFSET, 4096);
	TEST_ASSERT_EQ(KVM_EXEC_DISPATCH_MMAP_SIZE, 8192);
	TEST_ASSERT_EQ(offsetof(struct kvm_exec_run_dispatch, exit_sequence), 88);
	TEST_ASSERT_EQ(offsetof(struct kvm_exec_run_dispatch, exit_flags), 96);
}

static void test_dynamic_dispatch_mapping(int kvm_fd)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN |
				  KVM_EXEC_FEATURE_CROSS_VM_CHAIN |
				  KVM_EXEC_FEATURE_DYNAMIC_DISPATCH;
	struct kvm_exec_dispatch_header *header;
	uint64_t domain_generation, executor_generation;
	pid_t child;
	int domain_fd, executor_fd, status;

	domain_fd = create_domain_with_features(kvm_fd, 2, 1, features,
						&domain_generation);
	executor_fd = create_executor(domain_fd, 0x701, &executor_generation);
	child = fork();
	TEST_ASSERT(child >= 0, "fork failed, errno %d", errno);
	if (!child) {
		void *wrong_mm_mapping;

		errno = 0;
		wrong_mm_mapping = mmap(NULL, KVM_EXEC_DISPATCH_MMAP_SIZE,
					PROT_READ | PROT_WRITE, MAP_SHARED,
					executor_fd, 0);
		_exit(wrong_mm_mapping == MAP_FAILED && errno == EIO ? 0 : 1);
	}
	waitpid(child, &status, 0);
	TEST_ASSERT(WIFEXITED(status) && !WEXITSTATUS(status),
		    "wrong-mm executor mmap was not rejected");

	header = mmap(NULL, KVM_EXEC_DISPATCH_MMAP_SIZE, PROT_READ | PROT_WRITE,
		      MAP_SHARED, executor_fd, 0);
	TEST_ASSERT(header != MAP_FAILED, "executor mmap failed, errno: %d", errno);
	TEST_ASSERT_EQ(header->abi_version, KVM_EXEC_DISPATCH_ABI_VERSION);
	TEST_ASSERT_EQ(header->region_size, KVM_EXEC_DISPATCH_MMAP_SIZE);
	TEST_ASSERT_EQ(header->command_offset, KVM_EXEC_DISPATCH_COMMAND_OFFSET);
	TEST_ASSERT_EQ(header->completion_offset,
		       KVM_EXEC_DISPATCH_COMPLETION_OFFSET);
	TEST_ASSERT_EQ(header->command_entries, KVM_EXEC_DISPATCH_RING_ENTRIES);
	TEST_ASSERT_EQ(header->completion_entries, KVM_EXEC_DISPATCH_RING_ENTRIES);
	TEST_ASSERT_EQ(header->command_entry_size,
		       sizeof(struct kvm_exec_command));
	TEST_ASSERT_EQ(header->completion_entry_size,
		       sizeof(struct kvm_exec_completion));
	TEST_ASSERT_EQ(header->command_head, 0);
	TEST_ASSERT_EQ(header->command_tail, 0);
	TEST_ASSERT_EQ(header->completion_head, 0);
	TEST_ASSERT_EQ(header->completion_tail, 0);
	child = fork();
	TEST_ASSERT(child >= 0, "fork failed, errno %d", errno);
	if (!child) {
		unsigned char residency;

		errno = 0;
		_exit(mincore(header, 4096, &residency) == -1 &&
		      errno == ENOMEM ? 0 : 1);
	}
	waitpid(child, &status, 0);
	TEST_ASSERT(WIFEXITED(status) && !WEXITSTATUS(status),
		    "dispatch mapping survived into a different mm");

	close(executor_fd);
	TEST_ASSERT_EQ(header->abi_version, KVM_EXEC_DISPATCH_ABI_VERSION);
	munmap(header, KVM_EXEC_DISPATCH_MMAP_SIZE);
	close(domain_fd);
}

static void attach_vcpu(int domain_fd, int vcpu_fd, uint64_t capsule_id,
			uint64_t lifecycle_generation)
{
	struct kvm_exec_attach_vcpu attach = {
		.size = sizeof(attach),
		.vcpu_fd = vcpu_fd,
		.capsule_id = capsule_id,
		.lifecycle_generation = lifecycle_generation,
	};
	int ret = ioctl(domain_fd, KVM_EXEC_ATTACH_VCPU, &attach);

	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_ATTACH_VCPU, ret));
}

static void detach_vcpu(int domain_fd, uint64_t capsule_id,
			uint64_t lifecycle_generation)
{
	struct kvm_exec_detach_vcpu detach = {
		.size = sizeof(detach),
		.capsule_id = capsule_id,
		.lifecycle_generation = lifecycle_generation,
	};
	int ret = ioctl(domain_fd, KVM_EXEC_DETACH_VCPU, &detach);

	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_DETACH_VCPU, ret));
}

static int create_executor_on_cpu(int domain_fd, uint64_t cookie, uint32_t flags,
				  uint32_t requested_cpu,
				  uint64_t *generation)
{
	struct kvm_exec_create_executor create = {
		.size = sizeof(create),
		.flags = flags,
		.requested_cpu = requested_cpu,
		.executor_cookie = cookie,
	};
	int executor_fd = ioctl(domain_fd, KVM_EXEC_CREATE_EXECUTOR, &create);

	TEST_ASSERT(executor_fd >= 0,
		    KVM_IOCTL_ERROR(KVM_EXEC_CREATE_EXECUTOR, executor_fd));
	TEST_ASSERT(create.executor_generation,
		    "KVM returned a zero executor generation");
	*generation = create.executor_generation;
	return executor_fd;
}

static int create_executor(int domain_fd, uint64_t cookie,
			   uint64_t *generation)
{
	return create_executor_on_cpu(domain_fd, cookie, 0, KVM_EXEC_CPU_ANY,
				      generation);
}

static void control_domain(int domain_fd, unsigned long request)
{
	struct kvm_exec_domain_control control = {
		.size = sizeof(control),
	};
	int ret = ioctl(domain_fd, request, &control);

	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(request, ret));
}

static void disable_nested_cpuid(struct kvm_vcpu *vcpu)
{
	if (kvm_cpu_has(X86_FEATURE_VMX))
		vcpu_clear_cpuid_feature(vcpu, X86_FEATURE_VMX);
	if (kvm_cpu_has(X86_FEATURE_SVM))
		vcpu_clear_cpuid_feature(vcpu, X86_FEATURE_SVM);
}

static uint64_t vcpu_get_stat(int stats_fd, const char *stat_name)
{
	struct kvm_stats_header header;
	struct kvm_stats_desc *descriptors, *descriptor;
	uint64_t data = 0;
	size_t descriptor_size;
	int i;

	read_stats_header(stats_fd, &header);
	descriptors = read_stats_descriptors(stats_fd, &header);
	descriptor_size = get_stats_descriptor_size(&header);

	for (i = 0; i < header.num_desc; i++) {
		descriptor = (void *)descriptors + i * descriptor_size;
		if (strcmp(descriptor->name, stat_name))
			continue;
		read_stat_data(stats_fd, &header, descriptor, &data, 1);
		free(descriptors);
		return data;
	}

	free(descriptors);
	TEST_FAIL("vCPU statistic '%s' is unavailable", stat_name);
	return 0;
}

static void guest_two_exits(void)
{
	GUEST_SYNC(1);
	GUEST_DONE();
}

static uint64_t trace_counts[4];
static uint64_t trace_state_errors[4];
static uint64_t trace_stacks[4];
static uint64_t trace_stack_errors[4];
static uint64_t trace_last_tsc[4];
static uint64_t trace_tsc_errors[4];
static uint64_t trace_nmi_counts[4];
static uint64_t trace_nmi_errors;
static uint64_t trace_irq_counts[4];
static uint64_t trace_irq_errors;

#define TRACE_IRQ_VECTOR 0x40

static void guest_trace_nmi_handler(struct ex_regs *regs)
{
	if (regs->rdi < ARRAY_SIZE(trace_nmi_counts))
		trace_nmi_counts[regs->rdi]++;
	else
		trace_nmi_errors++;
}

static void guest_trace_irq_handler(struct ex_regs *regs)
{
	if (regs->rdi < ARRAY_SIZE(trace_irq_counts))
		trace_irq_counts[regs->rdi]++;
	else
		trace_irq_errors++;
}

static void guest_single_step_trace(uint64_t id)
{
	register uint64_t signature asm("r12") = 0x5a5a000000000000ULL | id;
	const uint64_t expected = signature;

	for (;;) {
		uint64_t now = rdtsc();
		uint64_t stack;

		asm volatile("mov %%rsp, %0" : "=r"(stack));

		WRITE_ONCE(trace_counts[id], READ_ONCE(trace_counts[id]) + 1);
		asm volatile("pause" : "+r"(signature) : : "memory");
		if (signature != expected)
			WRITE_ONCE(trace_state_errors[id], signature);
		if (!READ_ONCE(trace_stacks[id]))
			WRITE_ONCE(trace_stacks[id], stack);
		else if (READ_ONCE(trace_stacks[id]) != stack)
			WRITE_ONCE(trace_stack_errors[id], stack);
		if (READ_ONCE(trace_last_tsc[id]) > now)
			WRITE_ONCE(trace_tsc_errors[id], 1);
		WRITE_ONCE(trace_last_tsc[id], now);
	}
}

static void guest_interrupt_single_step_trace(uint64_t id)
{
	x2apic_enable();
	x2apic_write_reg(APIC_ICR, APIC_DEST_SELF | APIC_INT_ASSERT |
			 APIC_DM_FIXED | TRACE_IRQ_VECTOR);
	asm volatile("sti");
	guest_single_step_trace(id);
}

static void test_same_vm_single_step_trace(int kvm_fd)
{
	const uint32_t repeats = 4096;
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN;
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	struct kvm_exec_trace_entry entries[2] = {
		{
			.capsule_id = 11,
			.lifecycle_generation = 3,
			.user_cookie = 0xa,
		},
		{
			.capsule_id = 12,
			.lifecycle_generation = 4,
			.user_cookie = 0xb,
		},
	};
	struct kvm_exec_run_trace trace = {
		.size = sizeof(trace),
		.request_sequence = 1,
		.entries = (uintptr_t)entries,
		.nr_entries = ARRAY_SIZE(entries),
		.repeat_count = repeats,
		.user_cookie = 0x55aa,
	};
	static const uint64_t gpr_signatures[2] = {
		0x5a5a000000000000ULL, 0x5a5a000000000001ULL,
	};
	static const uint64_t debug_signatures[2] = {
		0x1111222233334444ULL, 0xaaaabbbbccccddddULL,
	};
	static const uint64_t xmm_signatures[2][2] = {
		{ 0x0123456789abcdefULL, 0xfedcba9876543210ULL },
		{ 0x8877665544332211ULL, 0x1122334455667788ULL },
	};
	struct kvm_debugregs debugregs[2], observed_debugregs;
	struct kvm_fpu fpu[2], observed_fpu;
	struct kvm_regs regs[2], observed_regs;
	uint64_t *counts, *errors, *stacks, *stack_errors, *tsc_errors;
	uint64_t *nmi_counts, *nmi_errors;
	struct kvm_vcpu *a, *b;
	struct kvm_vcpu *vcpus[2];
	struct kvm_vm *vm;
	uint64_t domain_generation, executor_generation;
	int domain_fd, executor_fd, ret, i;

	vm = vm_create_with_one_vcpu(&a, guest_single_step_trace);
	b = vm_vcpu_add(vm, 1, guest_single_step_trace);
	vcpu_args_set(a, 1, 0);
	vcpu_args_set(b, 1, 1);
	vcpus[0] = a;
	vcpus[1] = b;
	disable_nested_cpuid(a);
	disable_nested_cpuid(b);
	vm_init_descriptor_tables(vm);
	vcpu_init_descriptor_tables(a);
	vcpu_init_descriptor_tables(b);
	vm_install_exception_handler(vm, NMI_VECTOR,
				     guest_trace_nmi_handler);
	vcpu_guest_debug_set(a, &debug);
	vcpu_guest_debug_set(b, &debug);
	counts = addr_gva2hva(vm, (vm_vaddr_t)trace_counts);
	errors = addr_gva2hva(vm, (vm_vaddr_t)trace_state_errors);
	stacks = addr_gva2hva(vm, (vm_vaddr_t)trace_stacks);
	stack_errors = addr_gva2hva(vm, (vm_vaddr_t)trace_stack_errors);
	tsc_errors = addr_gva2hva(vm, (vm_vaddr_t)trace_tsc_errors);
	nmi_counts = addr_gva2hva(vm, (vm_vaddr_t)trace_nmi_counts);
	nmi_errors = addr_gva2hva(vm, (vm_vaddr_t)&trace_nmi_errors);
	memset(counts, 0, sizeof(trace_counts));
	memset(errors, 0, sizeof(trace_state_errors));
	memset(stacks, 0, sizeof(trace_stacks));
	memset(stack_errors, 0, sizeof(trace_stack_errors));
	memset(addr_gva2hva(vm, (vm_vaddr_t)trace_last_tsc), 0,
	       sizeof(trace_last_tsc));
	memset(tsc_errors, 0, sizeof(trace_tsc_errors));
	memset(nmi_counts, 0, sizeof(trace_nmi_counts));
	WRITE_ONCE(*nmi_errors, 0);
	for (i = 0; i < 2; i++) {
		vcpu_regs_get(vcpus[i], &regs[i]);
		regs[i].r12 = gpr_signatures[i];
		vcpu_regs_set(vcpus[i], &regs[i]);
		vcpu_debugregs_get(vcpus[i], &debugregs[i]);
		debugregs[i].db[0] = debug_signatures[i];
		vcpu_debugregs_set(vcpus[i], &debugregs[i]);
		vcpu_fpu_get(vcpus[i], &fpu[i]);
		memcpy(fpu[i].xmm[15], xmm_signatures[i],
		       sizeof(xmm_signatures[i]));
		vcpu_fpu_set(vcpus[i], &fpu[i]);
		ret = ioctl(vcpus[i]->fd, KVM_NMI, 0);
		TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_NMI, ret));
	}

	domain_fd = create_domain_with_features(kvm_fd, 2, 1, features,
						&domain_generation);
	attach_vcpu(domain_fd, a->fd, 11, 3);
	attach_vcpu(domain_fd, b->fd, 12, 4);
	executor_fd = create_executor(domain_fd, 0x55aa,
				      &executor_generation);
	trace.domain_generation = domain_generation;
	trace.executor_generation = executor_generation;

	ret = ioctl(executor_fd, KVM_EXEC_RUN_TRACE, &trace);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN_TRACE, ret));
	TEST_ASSERT_EQ(trace.return_reason, KVM_EXEC_RETURN_TRACE_COMPLETE);
	TEST_ASSERT_EQ(trace.run_result, 0);
	TEST_ASSERT_EQ(trace.vcpu_exit_reason, KVM_EXIT_DEBUG);
	TEST_ASSERT_EQ(trace.owned_capsule_id, 12);
	TEST_ASSERT_EQ(trace.owned_lifecycle_generation, 4);
	TEST_ASSERT_EQ(trace.completed_steps, 2ULL * repeats);
	TEST_ASSERT_EQ(trace.switch_count, 2ULL * repeats - 1);
	TEST_ASSERT(trace.first_switch_ns &&
		    trace.last_switch_ns >= trace.first_switch_ns,
		    "invalid trace switch timestamps");
	TEST_ASSERT(READ_ONCE(counts[0]) > 0,
		    "first trace vCPU made no guest progress");
	TEST_ASSERT(READ_ONCE(counts[1]) > 0,
		    "second trace vCPU made no guest progress");
	TEST_ASSERT_EQ(READ_ONCE(errors[0]), 0);
	TEST_ASSERT_EQ(READ_ONCE(errors[1]), 0);
	TEST_ASSERT_EQ(READ_ONCE(stack_errors[0]), 0);
	TEST_ASSERT_EQ(READ_ONCE(stack_errors[1]), 0);
	TEST_ASSERT_EQ(READ_ONCE(tsc_errors[0]), 0);
	TEST_ASSERT_EQ(READ_ONCE(tsc_errors[1]), 0);
	TEST_ASSERT_EQ(READ_ONCE(nmi_counts[0]), 1);
	TEST_ASSERT_EQ(READ_ONCE(nmi_counts[1]), 1);
	TEST_ASSERT_EQ(READ_ONCE(*nmi_errors), 0);

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	for (i = 0; i < 2; i++) {
		vcpu_regs_get(vcpus[i], &observed_regs);
		TEST_ASSERT_EQ(observed_regs.rsp, READ_ONCE(stacks[i]));
		TEST_ASSERT_EQ(observed_regs.r12, gpr_signatures[i]);
		vcpu_debugregs_get(vcpus[i], &observed_debugregs);
		TEST_ASSERT_EQ(observed_debugregs.db[0], debug_signatures[i]);
		vcpu_fpu_get(vcpus[i], &observed_fpu);
		TEST_ASSERT(!memcmp(observed_fpu.xmm[15], xmm_signatures[i],
				    sizeof(xmm_signatures[i])),
			    "vCPU %d XMM15 signature changed", i);
	}
	detach_vcpu(domain_fd, 11, 3);
	detach_vcpu(domain_fd, 12, 4);
	close(executor_fd);
	close(domain_fd);
	kvm_vm_free(vm);
}

static void test_trace_validation_and_cross_vm_rejection(int kvm_fd)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN;
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	struct kvm_exec_trace_entry entries[2] = {
		{ .capsule_id = 1, .lifecycle_generation = 1 },
		{ .capsule_id = 2, .lifecycle_generation = 1 },
	};
	struct kvm_exec_run_trace trace = {
		.size = sizeof(trace),
		.request_sequence = 1,
		.entries = (uintptr_t)entries,
		.nr_entries = ARRAY_SIZE(entries),
		.repeat_count = 1,
	};
	struct kvm_vcpu *a, *b;
	struct kvm_vm *vm_a, *vm_b;
	uint64_t domain_generation, executor_generation;
	int domain_fd, executor_fd;

	vm_a = vm_create_with_one_vcpu(&a, guest_single_step_trace);
	vm_b = vm_create_with_one_vcpu(&b, guest_single_step_trace);
	vcpu_args_set(a, 1, 0);
	vcpu_args_set(b, 1, 1);
	disable_nested_cpuid(a);
	disable_nested_cpuid(b);
	vcpu_guest_debug_set(a, &debug);
	vcpu_guest_debug_set(b, &debug);
	domain_fd = create_domain_with_features(kvm_fd, 2, 1, features,
						&domain_generation);
	attach_vcpu(domain_fd, a->fd, 1, 1);
	attach_vcpu(domain_fd, b->fd, 2, 1);
	executor_fd = create_executor(domain_fd, 1, &executor_generation);
	trace.domain_generation = domain_generation;
	trace.executor_generation = executor_generation;

	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, EXDEV);
	trace.entries = 0;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, EFAULT);
	trace.entries = (uintptr_t)entries;
	trace.size--;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, EINVAL);
	trace.size++;
	trace.flags = 1;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, EINVAL);
	trace.flags = 0;
	trace.repeat_count = 0;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, EINVAL);
	trace.repeat_count = KVM_EXEC_TRACE_MAX_STEPS;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, E2BIG);
	trace.repeat_count = 1;
	trace.nr_entries = KVM_EXEC_TRACE_MAX_ENTRIES + 1;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, E2BIG);
	trace.nr_entries = ARRAY_SIZE(entries);
	entries[0].reserved = 1;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, EINVAL);
	entries[0].reserved = 0;
	trace.reserved[0] = 1;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, EINVAL);

	close(executor_fd);
	detach_vcpu(domain_fd, 1, 1);
	detach_vcpu(domain_fd, 2, 1);
	close(domain_fd);
	kvm_vm_free(vm_b);
	kvm_vm_free(vm_a);
}

static void test_cross_vm_single_step_trace(int kvm_fd)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN |
				  KVM_EXEC_FEATURE_CROSS_VM_CHAIN;
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	struct kvm_exec_trace_entry entries[2] = {
		{ .capsule_id = 101, .lifecycle_generation = 11 },
		{ .capsule_id = 202, .lifecycle_generation = 22 },
	};
	struct kvm_exec_run_trace trace = {
		.size = sizeof(trace),
		.request_sequence = 1,
		.entries = (uintptr_t)entries,
		.nr_entries = ARRAY_SIZE(entries),
		.repeat_count = 64,
	};
	struct kvm_vcpu *a, *b;
	struct kvm_vm *vm_a, *vm_b;
	uint64_t domain_generation, executor_generation;
	int domain_fd, executor_fd, ret;

	vm_a = vm_create_with_one_vcpu(&a, guest_single_step_trace);
	vm_b = vm_create_with_one_vcpu(&b, guest_single_step_trace);
	vcpu_args_set(a, 1, 0);
	vcpu_args_set(b, 1, 1);
	disable_nested_cpuid(a);
	disable_nested_cpuid(b);
	vcpu_guest_debug_set(a, &debug);
	vcpu_guest_debug_set(b, &debug);

	domain_fd = create_domain_with_features(kvm_fd, 2, 1, features,
						&domain_generation);
	attach_vcpu(domain_fd, a->fd, 101, 11);
	attach_vcpu(domain_fd, b->fd, 202, 22);
	executor_fd = create_executor(domain_fd, 0xc055,
				      &executor_generation);
	trace.domain_generation = domain_generation;
	trace.executor_generation = executor_generation;

	ret = ioctl(executor_fd, KVM_EXEC_RUN_TRACE, &trace);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN_TRACE, ret));
	TEST_ASSERT_EQ(trace.return_reason, KVM_EXEC_RETURN_TRACE_COMPLETE);
	TEST_ASSERT_EQ(trace.run_result, 0);
	TEST_ASSERT_EQ(trace.vcpu_exit_reason, KVM_EXIT_DEBUG);
	TEST_ASSERT_EQ(trace.completed_steps, 128);
	TEST_ASSERT_EQ(trace.switch_count, 127);
	TEST_ASSERT_EQ(trace.owned_capsule_id, 202);
	TEST_ASSERT_EQ(trace.owned_lifecycle_generation, 22);

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	detach_vcpu(domain_fd, 101, 11);
	detach_vcpu(domain_fd, 202, 22);
	close(executor_fd);
	close(domain_fd);
	kvm_vm_free(vm_b);
	kvm_vm_free(vm_a);
}

static uint64_t expected_trace_switches(struct kvm_exec_trace_entry *entries,
					uint32_t nr_entries,
					uint32_t repeat_count)
{
	uint64_t steps = (uint64_t)nr_entries * repeat_count;
	uint64_t switches = 0;
	uint64_t step;

	for (step = 1; step < steps; step++) {
		struct kvm_exec_trace_entry *previous =
			&entries[(step - 1) % nr_entries];
		struct kvm_exec_trace_entry *current =
			&entries[step % nr_entries];

		if (previous->capsule_id != current->capsule_id)
			switches++;
	}
	return switches;
}

static void test_cross_vm_state_and_seeded_traces(int kvm_fd)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN |
				  KVM_EXEC_FEATURE_CROSS_VM_CHAIN;
	const uint64_t capsule_ids[4] = { 100, 200, 101, 201 };
	const uint64_t generations[4] = { 10, 20, 11, 21 };
	static const uint64_t debug_signatures[4] = {
		0x1000100010001000ULL, 0x2000200020002000ULL,
		0x3000300030003000ULL, 0x4000400040004000ULL,
	};
	static const uint64_t xmm_signatures[4][2] = {
		{ 0x0011223344556677ULL, 0x8899aabbccddeeffULL },
		{ 0x1021324354657687ULL, 0x98a9bacbdcedfe0fULL },
		{ 0x2132435465768798ULL, 0xa9bacbdcedfe0f10ULL },
		{ 0x32435465768798a9ULL, 0xbacbdcedfe0f1021ULL },
	};
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	struct kvm_exec_trace_entry fixed_entries[4];
	struct kvm_exec_trace_entry seeded_entries[128];
	struct kvm_exec_run_trace trace = {
		.size = sizeof(trace),
		.request_sequence = 1,
		.entries = (uintptr_t)fixed_entries,
		.nr_entries = ARRAY_SIZE(fixed_entries),
		.repeat_count = 2048,
		.user_cookie = 0xc055600d,
	};
	struct kvm_debugregs debugregs[4], observed_debugregs;
	struct kvm_fpu fpu[4], observed_fpu;
	struct kvm_regs regs[4], observed_regs;
	struct kvm_vcpu *vcpus[4];
	void *guest_code = guest_interrupt_single_step_trace;
	uint64_t exits_before[4];
	struct kvm_vm *vm_a, *vm_b;
	uint64_t *counts[2], *errors[2], *stacks[2], *stack_errors[2];
	uint64_t *tsc_errors[2], *nmi_counts[2], *nmi_errors[2];
	uint64_t *irq_counts[2], *irq_errors[2];
	uint64_t domain_generation, executor_generation;
	uint64_t expected_switches;
	int domain_fd, executor_fd, stats_fds[4], ret, i, vm_index;

	vm_a = vm_create_with_one_vcpu(&vcpus[0], guest_code);
	vcpus[2] = vm_vcpu_add(vm_a, 1, guest_code);
	vm_b = vm_create_with_one_vcpu(&vcpus[1], guest_code);
	vcpus[3] = vm_vcpu_add(vm_b, 1, guest_code);

	for (i = 0; i < 4; i++) {
		vcpu_args_set(vcpus[i], 1, i);
		disable_nested_cpuid(vcpus[i]);
		vcpu_guest_debug_set(vcpus[i], &debug);
		fixed_entries[i] = (struct kvm_exec_trace_entry) {
			.capsule_id = capsule_ids[i],
			.lifecycle_generation = generations[i],
			.user_cookie = i,
		};
	}

	vm_init_descriptor_tables(vm_a);
	vm_init_descriptor_tables(vm_b);
	for (i = 0; i < 4; i++)
		vcpu_init_descriptor_tables(vcpus[i]);
	vm_install_exception_handler(vm_a, NMI_VECTOR,
				     guest_trace_nmi_handler);
	vm_install_exception_handler(vm_b, NMI_VECTOR,
				     guest_trace_nmi_handler);
	vm_install_exception_handler(vm_a, TRACE_IRQ_VECTOR,
				     guest_trace_irq_handler);
	vm_install_exception_handler(vm_b, TRACE_IRQ_VECTOR,
				     guest_trace_irq_handler);

	for (vm_index = 0; vm_index < 2; vm_index++) {
		struct kvm_vm *vm = vm_index ? vm_b : vm_a;

		counts[vm_index] = addr_gva2hva(vm, (vm_vaddr_t)trace_counts);
		errors[vm_index] =
			addr_gva2hva(vm, (vm_vaddr_t)trace_state_errors);
		stacks[vm_index] = addr_gva2hva(vm, (vm_vaddr_t)trace_stacks);
		stack_errors[vm_index] =
			addr_gva2hva(vm, (vm_vaddr_t)trace_stack_errors);
		tsc_errors[vm_index] =
			addr_gva2hva(vm, (vm_vaddr_t)trace_tsc_errors);
		nmi_counts[vm_index] =
			addr_gva2hva(vm, (vm_vaddr_t)trace_nmi_counts);
		nmi_errors[vm_index] =
			addr_gva2hva(vm, (vm_vaddr_t)&trace_nmi_errors);
		irq_counts[vm_index] =
			addr_gva2hva(vm, (vm_vaddr_t)trace_irq_counts);
		irq_errors[vm_index] =
			addr_gva2hva(vm, (vm_vaddr_t)&trace_irq_errors);
		memset(counts[vm_index], 0, sizeof(trace_counts));
		memset(errors[vm_index], 0, sizeof(trace_state_errors));
		memset(stacks[vm_index], 0, sizeof(trace_stacks));
		memset(stack_errors[vm_index], 0,
		       sizeof(trace_stack_errors));
		memset(addr_gva2hva(vm, (vm_vaddr_t)trace_last_tsc), 0,
		       sizeof(trace_last_tsc));
		memset(tsc_errors[vm_index], 0, sizeof(trace_tsc_errors));
		memset(nmi_counts[vm_index], 0, sizeof(trace_nmi_counts));
		WRITE_ONCE(*nmi_errors[vm_index], 0);
		memset(irq_counts[vm_index], 0, sizeof(trace_irq_counts));
		WRITE_ONCE(*irq_errors[vm_index], 0);
	}

	for (i = 0; i < 4; i++) {
		vcpu_regs_get(vcpus[i], &regs[i]);
		regs[i].r12 = 0x5a5a000000000000ULL | i;
		vcpu_regs_set(vcpus[i], &regs[i]);
		vcpu_debugregs_get(vcpus[i], &debugregs[i]);
		debugregs[i].db[0] = debug_signatures[i];
		vcpu_debugregs_set(vcpus[i], &debugregs[i]);
		vcpu_fpu_get(vcpus[i], &fpu[i]);
		memcpy(fpu[i].xmm[15], xmm_signatures[i],
		       sizeof(xmm_signatures[i]));
		vcpu_fpu_set(vcpus[i], &fpu[i]);
		ret = ioctl(vcpus[i]->fd, KVM_NMI, 0);
		TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_NMI, ret));
		stats_fds[i] = vcpu_get_stats_fd(vcpus[i]);
		exits_before[i] = vcpu_get_stat(stats_fds[i], "exits");
	}

	domain_fd = create_domain_with_features(kvm_fd, 4, 1, features,
						&domain_generation);
	for (i = 0; i < 4; i++)
		attach_vcpu(domain_fd, vcpus[i]->fd, capsule_ids[i],
			    generations[i]);
	executor_fd = create_executor(domain_fd, 0xc055600d,
				      &executor_generation);
	trace.domain_generation = domain_generation;
	trace.executor_generation = executor_generation;

	ret = ioctl(executor_fd, KVM_EXEC_RUN_TRACE, &trace);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN_TRACE, ret));
	TEST_ASSERT_EQ(trace.return_reason, KVM_EXEC_RETURN_TRACE_COMPLETE);
	TEST_ASSERT_EQ(trace.run_result, 0);
	TEST_ASSERT_EQ(trace.completed_steps, 8192);
	TEST_ASSERT_EQ(trace.switch_count, 8191);
	TEST_ASSERT_EQ(trace.owned_capsule_id, capsule_ids[3]);

	TEST_ASSERT(READ_ONCE(counts[0][0]) > 0 &&
		    READ_ONCE(counts[0][2]) > 0,
		    "VM A capsules made no progress");
	TEST_ASSERT_EQ(READ_ONCE(counts[0][1]), 0);
	TEST_ASSERT_EQ(READ_ONCE(counts[0][3]), 0);
	TEST_ASSERT(READ_ONCE(counts[1][1]) > 0 &&
		    READ_ONCE(counts[1][3]) > 0,
		    "VM B capsules made no progress");
	TEST_ASSERT_EQ(READ_ONCE(counts[1][0]), 0);
	TEST_ASSERT_EQ(READ_ONCE(counts[1][2]), 0);
	for (i = 0; i < 4; i++) {
		vm_index = i & 1;
		TEST_ASSERT_EQ(READ_ONCE(errors[vm_index][i]), 0);
		TEST_ASSERT_EQ(READ_ONCE(stack_errors[vm_index][i]), 0);
		TEST_ASSERT_EQ(READ_ONCE(tsc_errors[vm_index][i]), 0);
		TEST_ASSERT_EQ(READ_ONCE(nmi_counts[vm_index][i]), 1);
		TEST_ASSERT_EQ(READ_ONCE(irq_counts[vm_index][i]), 1);
	}
	TEST_ASSERT_EQ(READ_ONCE(*nmi_errors[0]), 0);
	TEST_ASSERT_EQ(READ_ONCE(*nmi_errors[1]), 0);
	TEST_ASSERT_EQ(READ_ONCE(*irq_errors[0]), 0);
	TEST_ASSERT_EQ(READ_ONCE(*irq_errors[1]), 0);

	seeded_entries[0] = fixed_entries[3];
	for (i = 1; i < ARRAY_SIZE(seeded_entries); i++) {
		uint32_t selected = fuzz_next() % ARRAY_SIZE(fixed_entries);

		seeded_entries[i] = fixed_entries[selected];
		seeded_entries[i].user_cookie = fuzz_state;
	}
	trace.request_sequence = 2;
	trace.entries = (uintptr_t)seeded_entries;
	trace.nr_entries = ARRAY_SIZE(seeded_entries);
	trace.repeat_count = 32;
	expected_switches = expected_trace_switches(seeded_entries,
						    ARRAY_SIZE(seeded_entries),
						    trace.repeat_count);
	ret = ioctl(executor_fd, KVM_EXEC_RUN_TRACE, &trace);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN_TRACE, ret));
	TEST_ASSERT_EQ(trace.return_reason, KVM_EXEC_RETURN_TRACE_COMPLETE);
	TEST_ASSERT_EQ(trace.completed_steps,
		       (uint64_t)ARRAY_SIZE(seeded_entries) * trace.repeat_count);
	TEST_ASSERT_EQ(trace.switch_count, expected_switches);
	TEST_ASSERT_EQ(trace.owned_capsule_id,
		       seeded_entries[ARRAY_SIZE(seeded_entries) - 1].capsule_id);

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	for (i = 0; i < 4; i++) {
		vm_index = i & 1;
		TEST_ASSERT(vcpu_get_stat(stats_fds[i], "exits") > exits_before[i],
			    "cross-VM vCPU %d exit accounting did not advance", i);
		vcpu_regs_get(vcpus[i], &observed_regs);
		TEST_ASSERT_EQ(observed_regs.rsp,
			       READ_ONCE(stacks[vm_index][i]));
		TEST_ASSERT_EQ(observed_regs.r12,
			       0x5a5a000000000000ULL | i);
		vcpu_debugregs_get(vcpus[i], &observed_debugregs);
		TEST_ASSERT_EQ(observed_debugregs.db[0], debug_signatures[i]);
		vcpu_fpu_get(vcpus[i], &observed_fpu);
		TEST_ASSERT(!memcmp(observed_fpu.xmm[15], xmm_signatures[i],
				    sizeof(xmm_signatures[i])),
			    "cross-VM vCPU %d XMM15 signature changed", i);
		detach_vcpu(domain_fd, capsule_ids[i], generations[i]);
		close(stats_fds[i]);
	}
	close(executor_fd);
	close(domain_fd);
	kvm_vm_free(vm_b);
	kvm_vm_free(vm_a);
}

static void test_base_only_domain_rejects_trace(int kvm_fd)
{
	struct kvm_exec_trace_entry entry = {
		.capsule_id = 1,
		.lifecycle_generation = 1,
	};
	struct kvm_exec_run_trace trace = {
		.size = sizeof(trace),
		.request_sequence = 1,
		.entries = (uintptr_t)&entry,
		.nr_entries = 1,
		.repeat_count = 1,
	};
	uint64_t domain_generation, executor_generation;
	int domain_fd, executor_fd;

	domain_fd = create_domain(kvm_fd, 1, 1, &domain_generation);
	executor_fd = create_executor(domain_fd, 1, &executor_generation);
	trace.domain_generation = domain_generation;
	trace.executor_generation = executor_generation;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace,
			   EOPNOTSUPP);

	close(executor_fd);
	close(domain_fd);
}

static void test_trace_stale_and_current_owner_rejection(int kvm_fd)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN;
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	struct kvm_exec_trace_entry entry = {
		.capsule_id = 31,
		.lifecycle_generation = 7,
	};
	struct kvm_exec_run_trace trace = {
		.size = sizeof(trace),
		.request_sequence = 1,
		.entries = (uintptr_t)&entry,
		.nr_entries = 1,
		.repeat_count = 1,
	};
	struct kvm_vcpu *a, *b;
	struct kvm_vm *vm;
	uint64_t domain_generation, executor_generation;
	int domain_fd, executor_fd, ret;

	vm = vm_create_with_one_vcpu(&a, guest_single_step_trace);
	b = vm_vcpu_add(vm, 1, guest_single_step_trace);
	vcpu_args_set(a, 1, 0);
	vcpu_args_set(b, 1, 1);
	disable_nested_cpuid(a);
	disable_nested_cpuid(b);
	vcpu_guest_debug_set(a, &debug);
	vcpu_guest_debug_set(b, &debug);
	domain_fd = create_domain_with_features(kvm_fd, 2, 1, features,
						&domain_generation);
	attach_vcpu(domain_fd, a->fd, 31, 7);
	attach_vcpu(domain_fd, b->fd, 32, 9);
	executor_fd = create_executor(domain_fd, 1, &executor_generation);
	trace.domain_generation = domain_generation + 1;
	trace.executor_generation = executor_generation;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, ESTALE);
	trace.domain_generation = domain_generation;
	trace.executor_generation = executor_generation + 1;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, ESTALE);
	trace.executor_generation = executor_generation;
	entry.lifecycle_generation++;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, ESTALE);
	entry.lifecycle_generation--;

	ret = ioctl(executor_fd, KVM_EXEC_RUN_TRACE, &trace);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN_TRACE, ret));
	TEST_ASSERT_EQ(trace.return_reason, KVM_EXEC_RETURN_TRACE_COMPLETE);
	TEST_ASSERT_EQ(trace.owned_capsule_id, 31);
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, ESTALE);

	trace.request_sequence = 2;
	entry.capsule_id = 32;
	entry.lifecycle_generation = 9;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &trace, EBUSY);

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	detach_vcpu(domain_fd, 31, 7);
	detach_vcpu(domain_fd, 32, 9);
	close(executor_fd);
	close(domain_fd);
	kvm_vm_free(vm);
}

static void guest_trace_io(void)
{
	GUEST_SYNC(1);
	GUEST_DONE();
}

#define TRACE_MMIO_GPA 0xc0000000ULL

static void guest_trace_mmio(void)
{
	(void)READ_ONCE(*(uint64_t *)TRACE_MMIO_GPA);
	GUEST_DONE();
}

static void test_trace_stops_on_non_debug_exit(int kvm_fd, void *guest_code,
					       uint32_t expected_exit)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN;
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	struct kvm_exec_trace_entry entry = {
		.capsule_id = 21,
		.lifecycle_generation = 1,
	};
	struct kvm_exec_run_trace trace = {
		.size = sizeof(trace),
		.request_sequence = 1,
		.entries = (uintptr_t)&entry,
		.nr_entries = 1,
		.repeat_count = 10000,
	};
	struct kvm_exec_run run = {
		.size = sizeof(run),
		.request_sequence = 2,
		.target_capsule_id = 21,
		.target_lifecycle_generation = 1,
	};
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint64_t domain_generation, executor_generation;
	int domain_fd, executor_fd, ret;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	disable_nested_cpuid(vcpu);
	vcpu_guest_debug_set(vcpu, &debug);
	domain_fd = create_domain_with_features(kvm_fd, 1, 1, features,
						&domain_generation);
	attach_vcpu(domain_fd, vcpu->fd, 21, 1);
	executor_fd = create_executor(domain_fd, 1, &executor_generation);
	trace.domain_generation = domain_generation;
	trace.executor_generation = executor_generation;

	ret = ioctl(executor_fd, KVM_EXEC_RUN_TRACE, &trace);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN_TRACE, ret));
	TEST_ASSERT_EQ(trace.return_reason, KVM_EXEC_RETURN_VCPU_EXIT);
	TEST_ASSERT_EQ(trace.run_result, 0);
	TEST_ASSERT_EQ(trace.vcpu_exit_reason, expected_exit);
	TEST_ASSERT(trace.completed_steps > 0 &&
		    trace.completed_steps < trace.repeat_count,
		    "non-debug exit advanced an invalid number of steps: %llu",
		    trace.completed_steps);
	TEST_ASSERT_EQ(trace.switch_count, 0);
	TEST_ASSERT_EQ(trace.owned_capsule_id, 21);

	if (expected_exit == KVM_EXIT_IO) {
		run.domain_generation = domain_generation;
		run.executor_generation = executor_generation;
		ret = ioctl(executor_fd, KVM_EXEC_RUN, &run);
		TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN, ret));
		TEST_ASSERT_EQ(run.return_reason, KVM_EXEC_RETURN_VCPU_EXIT);
		TEST_ASSERT_EQ(run.vcpu_exit_reason, KVM_EXIT_DEBUG);
	}

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	detach_vcpu(domain_fd, 21, 1);
	close(executor_fd);
	close(domain_fd);
	kvm_vm_free(vm);
}

static void test_trace_conservative_exits(int kvm_fd)
{
	test_trace_stops_on_non_debug_exit(kvm_fd, guest_trace_io,
					   KVM_EXIT_IO);
}

static void test_cross_vm_trace_stops_on_exit(int kvm_fd, void *guest_code,
					      uint32_t expected_exit)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN |
				  KVM_EXEC_FEATURE_CROSS_VM_CHAIN;
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	struct kvm_exec_trace_entry entries[2] = {
		{ .capsule_id = 61, .lifecycle_generation = 1 },
		{ .capsule_id = 62, .lifecycle_generation = 1 },
	};
	struct kvm_exec_run_trace trace = {
		.size = sizeof(trace),
		.request_sequence = 1,
		.entries = (uintptr_t)entries,
		.nr_entries = ARRAY_SIZE(entries),
		.repeat_count = 10000,
	};
	struct kvm_exec_run run = {
		.size = sizeof(run),
		.request_sequence = 2,
		.target_capsule_id = 61,
		.target_lifecycle_generation = 1,
	};
	struct kvm_vcpu *a, *b;
	struct kvm_vm *vm_a, *vm_b;
	uint64_t domain_generation, executor_generation;
	uint64_t *b_counts, b_count_at_exit;
	uint64_t b_exits_before, b_exits_at_exit;
	int domain_fd, executor_fd, b_stats_fd, ret;

	vm_a = vm_create_with_one_vcpu(&a, guest_code);
	vm_b = vm_create_with_one_vcpu(&b, guest_single_step_trace);
	vcpu_args_set(b, 1, 1);
	disable_nested_cpuid(a);
	disable_nested_cpuid(b);
	vcpu_guest_debug_set(a, &debug);
	vcpu_guest_debug_set(b, &debug);
	if (expected_exit == KVM_EXIT_MMIO)
		virt_map(vm_a, TRACE_MMIO_GPA, TRACE_MMIO_GPA, 1);
	b_counts = addr_gva2hva(vm_b, (vm_vaddr_t)trace_counts);
	memset(b_counts, 0, sizeof(trace_counts));
	b_stats_fd = vcpu_get_stats_fd(b);
	b_exits_before = vcpu_get_stat(b_stats_fd, "exits");

	domain_fd = create_domain_with_features(kvm_fd, 2, 1, features,
						&domain_generation);
	attach_vcpu(domain_fd, a->fd, 61, 1);
	attach_vcpu(domain_fd, b->fd, 62, 1);
	executor_fd = create_executor(domain_fd, 0xc055600e,
				      &executor_generation);
	trace.domain_generation = domain_generation;
	trace.executor_generation = executor_generation;

	ret = ioctl(executor_fd, KVM_EXEC_RUN_TRACE, &trace);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN_TRACE, ret));
	TEST_ASSERT_EQ(trace.return_reason, KVM_EXEC_RETURN_VCPU_EXIT);
	TEST_ASSERT_EQ(trace.run_result, 0);
	TEST_ASSERT_EQ(trace.vcpu_exit_reason, expected_exit);
	TEST_ASSERT_EQ(trace.owned_capsule_id, 61);
	TEST_ASSERT_EQ(a->run->exit_reason, expected_exit);
	TEST_ASSERT(trace.completed_steps > 0,
		    "cross-VM trace reached a device exit before any switch");
	TEST_ASSERT(trace.switch_count > 0,
		    "cross-VM trace reached a device exit without switching");
	b_count_at_exit = READ_ONCE(b_counts[1]);
	b_exits_at_exit = vcpu_get_stat(b_stats_fd, "exits");
	TEST_ASSERT(b_exits_at_exit > b_exits_before,
		    "VM B did not enter before VM A's device exit");

	if (expected_exit == KVM_EXIT_IO) {
		uint8_t pio_value = 0;

		TEST_ASSERT_EQ(a->run->io.direction, KVM_EXIT_IO_IN);
		TEST_ASSERT_EQ(a->run->io.size, sizeof(pio_value));
		TEST_ASSERT_EQ(a->run->io.count, 1);
		memcpy((uint8_t *)a->run + a->run->io.data_offset,
		       &pio_value, sizeof(pio_value));
	} else {
		uint64_t mmio_value = 0x5a5ac055600dULL;

		TEST_ASSERT_EQ(a->run->mmio.phys_addr, TRACE_MMIO_GPA);
		TEST_ASSERT_EQ(a->run->mmio.len, sizeof(mmio_value));
		TEST_ASSERT_EQ(a->run->mmio.is_write, 0);
		memcpy(a->run->mmio.data, &mmio_value, sizeof(mmio_value));
	}

	run.domain_generation = domain_generation;
	run.executor_generation = executor_generation;
	ret = ioctl(executor_fd, KVM_EXEC_RUN, &run);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN, ret));
	TEST_ASSERT_EQ(run.return_reason, KVM_EXEC_RETURN_VCPU_EXIT);
	TEST_ASSERT_EQ(run.vcpu_exit_reason, KVM_EXIT_DEBUG);
	TEST_ASSERT_EQ(run.owned_capsule_id, 61);
	TEST_ASSERT_EQ(READ_ONCE(b_counts[1]), b_count_at_exit);
	TEST_ASSERT_EQ(vcpu_get_stat(b_stats_fd, "exits"), b_exits_at_exit);

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	detach_vcpu(domain_fd, 61, 1);
	detach_vcpu(domain_fd, 62, 1);
	close(executor_fd);
	close(domain_fd);
	close(b_stats_fd);
	kvm_vm_free(vm_b);
	kvm_vm_free(vm_a);
}

static void test_cross_vm_conservative_exits(int kvm_fd)
{
	test_cross_vm_trace_stops_on_exit(kvm_fd, guest_trace_io,
					  KVM_EXIT_IO);
	test_cross_vm_trace_stops_on_exit(kvm_fd, guest_trace_mmio,
					  KVM_EXIT_MMIO);
}

#define TRACE_SLOT_GPA 0xd0000000ULL
#define TRACE_SLOT_ID 10
#define TRACE_SLOT_A_OLD 0xa0a0a0a0a0a0a0a0ULL
#define TRACE_SLOT_A_NEW 0xa1a1a1a1a1a1a1a1ULL
#define TRACE_SLOT_B 0xb0b0b0b0b0b0b0b0ULL

static uint64_t trace_slot_observations[2][2];
static uint64_t trace_slot_errors[2];

struct trace_run_arg {
	struct kvm_exec_run_trace trace;
	int executor_fd;
	int ret;
	int error;
};

static void *trace_runner(void *opaque)
{
	struct trace_run_arg *arg = opaque;

	errno = 0;
	arg->ret = ioctl(arg->executor_fd, KVM_EXEC_RUN_TRACE, &arg->trace);
	arg->error = errno;
	return NULL;
}

static void guest_trace_memslot(uint64_t id)
{
	for (;;) {
		uint64_t value = READ_ONCE(*(uint64_t *)TRACE_SLOT_GPA);

		if (!id && value == TRACE_SLOT_A_OLD)
			trace_slot_observations[0][0]++;
		else if (!id && value == TRACE_SLOT_A_NEW)
			trace_slot_observations[0][1]++;
		else if (id == 1 && value == TRACE_SLOT_B)
			trace_slot_observations[1][0]++;
		else
			trace_slot_errors[id] = value;
		asm volatile("pause" ::: "memory");
	}
}

static void test_cross_vm_memslot_update(int kvm_fd)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN |
				  KVM_EXEC_FEATURE_CROSS_VM_CHAIN;
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	struct kvm_exec_trace_entry entries[2] = {
		{ .capsule_id = 71, .lifecycle_generation = 1 },
		{ .capsule_id = 72, .lifecycle_generation = 1 },
	};
	struct kvm_userspace_memory_region slot = {
		.slot = TRACE_SLOT_ID,
		.guest_phys_addr = TRACE_SLOT_GPA,
		.memory_size = 4096,
	};
	struct trace_run_arg run_arg = { };
	struct kvm_vcpu *a, *b;
	struct kvm_vm *vm_a, *vm_b;
	uint64_t domain_generation, executor_generation;
	uint64_t (*a_observations)[2], (*b_observations)[2];
	uint64_t *a_errors, *b_errors, b_before_update;
	void *a_hva, *b_hva;
	pthread_t thread;
	int domain_fd, i;

	vm_a = vm_create_with_one_vcpu(&a, guest_trace_memslot);
	vm_b = vm_create_with_one_vcpu(&b, guest_trace_memslot);
	vcpu_args_set(a, 1, 0);
	vcpu_args_set(b, 1, 1);
	disable_nested_cpuid(a);
	disable_nested_cpuid(b);
	vcpu_guest_debug_set(a, &debug);
	vcpu_guest_debug_set(b, &debug);

	vm_userspace_mem_region_add(vm_a, VM_MEM_SRC_ANONYMOUS,
				    TRACE_SLOT_GPA, TRACE_SLOT_ID, 1, 0);
	vm_userspace_mem_region_add(vm_b, VM_MEM_SRC_ANONYMOUS,
				    TRACE_SLOT_GPA, TRACE_SLOT_ID, 1, 0);
	virt_map(vm_a, TRACE_SLOT_GPA, TRACE_SLOT_GPA, 1);
	virt_map(vm_b, TRACE_SLOT_GPA, TRACE_SLOT_GPA, 1);
	a_hva = addr_gpa2hva(vm_a, TRACE_SLOT_GPA);
	b_hva = addr_gpa2hva(vm_b, TRACE_SLOT_GPA);
	WRITE_ONCE(*(uint64_t *)a_hva, TRACE_SLOT_A_OLD);
	WRITE_ONCE(*(uint64_t *)b_hva, TRACE_SLOT_B);

	a_observations = addr_gva2hva(vm_a,
				      (vm_vaddr_t)trace_slot_observations);
	b_observations = addr_gva2hva(vm_b,
				      (vm_vaddr_t)trace_slot_observations);
	a_errors = addr_gva2hva(vm_a, (vm_vaddr_t)trace_slot_errors);
	b_errors = addr_gva2hva(vm_b, (vm_vaddr_t)trace_slot_errors);
	memset(a_observations, 0, sizeof(trace_slot_observations));
	memset(b_observations, 0, sizeof(trace_slot_observations));
	memset(a_errors, 0, sizeof(trace_slot_errors));
	memset(b_errors, 0, sizeof(trace_slot_errors));

	domain_fd = create_domain_with_features(kvm_fd, 2, 1, features,
						&domain_generation);
	attach_vcpu(domain_fd, a->fd, 71, 1);
	attach_vcpu(domain_fd, b->fd, 72, 1);
	run_arg.executor_fd = create_executor(domain_fd, 0xc055600f,
					      &executor_generation);
	run_arg.trace = (struct kvm_exec_run_trace) {
		.size = sizeof(run_arg.trace),
		.request_sequence = 1,
		.domain_generation = domain_generation,
		.executor_generation = executor_generation,
		.entries = (uintptr_t)entries,
		.nr_entries = ARRAY_SIZE(entries),
		.repeat_count = KVM_EXEC_TRACE_MAX_STEPS / ARRAY_SIZE(entries),
	};

	TEST_ASSERT(!pthread_create(&thread, NULL, trace_runner, &run_arg),
		    "pthread_create failed");
	for (i = 0; i < 1000000 &&
	     (!READ_ONCE(a_observations[0][0]) ||
	      !READ_ONCE(b_observations[1][0])); i++)
		sched_yield();
	TEST_ASSERT(READ_ONCE(a_observations[0][0]) &&
		    READ_ONCE(b_observations[1][0]),
		    "cross-VM trace did not observe initial slot mappings");
	b_before_update = READ_ONCE(b_observations[1][0]);

	WRITE_ONCE(*(uint64_t *)a_hva, TRACE_SLOT_A_NEW);
	slot.flags = KVM_MEM_LOG_DIRTY_PAGES;
	slot.userspace_addr = (uintptr_t)a_hva;
	vm_ioctl(vm_a, KVM_SET_USER_MEMORY_REGION, &slot);
	for (i = 0; i < 1000000 &&
	     !READ_ONCE(a_observations[0][1]); i++)
		sched_yield();
	TEST_ASSERT(READ_ONCE(a_observations[0][1]),
		    "VM A did not observe the replacement slot mapping");
	TEST_ASSERT(READ_ONCE(b_observations[1][0]) > b_before_update,
		    "VM B stopped progressing across VM A's slot update");

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	pthread_join(thread, NULL);
	TEST_ASSERT(!run_arg.ret,
		    "slot-update trace returned %d errno %d", run_arg.ret,
		    run_arg.error);
	TEST_ASSERT_EQ(run_arg.trace.return_reason,
		       KVM_EXEC_RETURN_DOMAIN_PAUSED);
	TEST_ASSERT(run_arg.trace.switch_count > 0,
		    "slot-update trace did not switch VMs");
	TEST_ASSERT_EQ(READ_ONCE(a_errors[0]), 0);
	TEST_ASSERT_EQ(READ_ONCE(b_errors[1]), 0);
	TEST_ASSERT_EQ(READ_ONCE(a_observations[1][0]), 0);
	TEST_ASSERT_EQ(READ_ONCE(b_observations[0][0]), 0);
	TEST_ASSERT_EQ(READ_ONCE(b_observations[0][1]), 0);

	slot.flags = 0;
	vm_ioctl(vm_a, KVM_SET_USER_MEMORY_REGION, &slot);
	detach_vcpu(domain_fd, 71, 1);
	detach_vcpu(domain_fd, 72, 1);
	close(run_arg.executor_fd);
	close(domain_fd);
	kvm_vm_free(vm_b);
	kvm_vm_free(vm_a);
}

static uint64_t trace_hlt_ready;

static void guest_trace_hlt(void)
{
	WRITE_ONCE(trace_hlt_ready, 1);
	asm volatile("hlt");
	GUEST_DONE();
}

static uint64_t trace_contention_ready;

static void guest_trace_contention(uint64_t id)
{
	if (!id)
		WRITE_ONCE(trace_contention_ready, 1);
	for (;;)
		asm volatile("pause");
}

static void test_trace_target_contention(int kvm_fd, bool cross_vm)
{
	uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
			    KVM_EXEC_FEATURE_INTRA_VM_CHAIN;
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	struct kvm_exec_trace_entry entries[KVM_EXEC_TRACE_MAX_ENTRIES];
	struct kvm_exec_run claim = {
		.size = sizeof(claim),
		.request_sequence = 1,
		.target_capsule_id = 42,
		.target_lifecycle_generation = 1,
	};
	struct trace_run_arg run_arg = { };
	struct kvm_vcpu *a, *b;
	struct kvm_vm *vm_a, *vm_b = NULL;
	uint64_t domain_generation, executor_generations[2];
	uint64_t *ready;
	pthread_t thread;
	int domain_fd, claim_executor_fd, ret, i;

	vm_a = vm_create_with_one_vcpu(&a, guest_trace_contention);
	if (cross_vm) {
		features |= KVM_EXEC_FEATURE_CROSS_VM_CHAIN;
		vm_b = vm_create_with_one_vcpu(&b, guest_trace_contention);
	} else {
		b = vm_vcpu_add(vm_a, 1, guest_trace_contention);
	}
	vcpu_args_set(a, 1, 0);
	vcpu_args_set(b, 1, 1);
	disable_nested_cpuid(a);
	disable_nested_cpuid(b);
	vcpu_guest_debug_set(a, &debug);
	vcpu_guest_debug_set(b, &debug);
	ready = addr_gva2hva(vm_a, (vm_vaddr_t)&trace_contention_ready);
	WRITE_ONCE(*ready, 0);
	for (i = 0; i < KVM_EXEC_TRACE_MAX_ENTRIES; i++) {
		entries[i].capsule_id = i + 1 == KVM_EXEC_TRACE_MAX_ENTRIES ?
					42 : 41;
		entries[i].lifecycle_generation = 1;
		entries[i].user_cookie = i;
		entries[i].reserved = 0;
	}

	domain_fd = create_domain_with_features(kvm_fd, 2, 2, features,
						&domain_generation);
	attach_vcpu(domain_fd, a->fd, 41, 1);
	attach_vcpu(domain_fd, b->fd, 42, 1);
	run_arg.executor_fd = create_executor(domain_fd, 1,
					      &executor_generations[0]);
	claim_executor_fd = create_executor(domain_fd, 2,
					    &executor_generations[1]);
	run_arg.trace = (struct kvm_exec_run_trace) {
		.size = sizeof(run_arg.trace),
		.request_sequence = 1,
		.domain_generation = domain_generation,
		.executor_generation = executor_generations[0],
		.entries = (uintptr_t)entries,
		.nr_entries = ARRAY_SIZE(entries),
		.repeat_count = 1,
	};
	claim.domain_generation = domain_generation;
	claim.executor_generation = executor_generations[1];

	TEST_ASSERT(!pthread_create(&thread, NULL, trace_runner, &run_arg),
		    "pthread_create failed");
	for (i = 0; i < 1000000 && !READ_ONCE(*ready); i++)
		sched_yield();
	TEST_ASSERT(READ_ONCE(*ready), "contention trace did not start");
	ret = ioctl(claim_executor_fd, KVM_EXEC_RUN, &claim);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN, ret));
	TEST_ASSERT_EQ(claim.return_reason, KVM_EXEC_RETURN_VCPU_EXIT);
	TEST_ASSERT_EQ(claim.owned_capsule_id, 42);
	pthread_join(thread, NULL);
	TEST_ASSERT(!run_arg.ret,
		    "contention trace returned %d errno %d", run_arg.ret,
		    run_arg.error);
	TEST_ASSERT_EQ(run_arg.trace.return_reason,
		       KVM_EXEC_RETURN_TRACE_TARGET_BUSY);
	TEST_ASSERT_EQ(run_arg.trace.run_result, -EBUSY);
	TEST_ASSERT_EQ(run_arg.trace.completed_steps,
		       KVM_EXEC_TRACE_MAX_ENTRIES - 1);
	TEST_ASSERT_EQ(run_arg.trace.switch_count, 0);
	TEST_ASSERT_EQ(run_arg.trace.owned_capsule_id, 41);

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	detach_vcpu(domain_fd, 41, 1);
	detach_vcpu(domain_fd, 42, 1);
	close(claim_executor_fd);
	close(run_arg.executor_fd);
	close(domain_fd);
	if (vm_b)
		kvm_vm_free(vm_b);
	kvm_vm_free(vm_a);
}

static void guest_trace_signal(void)
{
	for (;;)
		asm volatile("pause");
}

static void test_trace_signal_releases_references(int kvm_fd, bool cross_vm)
{
	uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
			    KVM_EXEC_FEATURE_INTRA_VM_CHAIN;
	struct sigaction action = {
		.sa_handler = signal_handler,
	};
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	struct kvm_exec_trace_entry entries[2] = {
		{ .capsule_id = 51, .lifecycle_generation = 1 },
		{ .capsule_id = 52, .lifecycle_generation = 1 },
	};
	struct kvm_exec_detach_vcpu detach[2] = {
		{
			.size = sizeof(detach[0]),
			.capsule_id = 51,
			.lifecycle_generation = 1,
		},
		{
			.size = sizeof(detach[1]),
			.capsule_id = 52,
			.lifecycle_generation = 1,
		},
	};
	struct trace_run_arg run_arg = { };
	struct kvm_vcpu *a, *b = NULL;
	struct kvm_vm *vm_a, *vm_b = NULL;
	uint64_t domain_generation, executor_generation;
	uint64_t exits_before[2];
	pthread_t thread;
	int domain_fd, stats_fds[2], i;

	sigemptyset(&action.sa_mask);
	TEST_ASSERT(!sigaction(SIGUSR1, &action, NULL),
		    "sigaction failed, errno %d", errno);
	vm_a = vm_create_with_one_vcpu(&a, guest_trace_signal);
	disable_nested_cpuid(a);
	vcpu_guest_debug_set(a, &debug);
	stats_fds[0] = vcpu_get_stats_fd(a);
	exits_before[0] = vcpu_get_stat(stats_fds[0], "exits");
	if (cross_vm) {
		features |= KVM_EXEC_FEATURE_CROSS_VM_CHAIN;
		vm_b = vm_create_with_one_vcpu(&b, guest_trace_signal);
		disable_nested_cpuid(b);
		vcpu_guest_debug_set(b, &debug);
		stats_fds[1] = vcpu_get_stats_fd(b);
		exits_before[1] = vcpu_get_stat(stats_fds[1], "exits");
	}
	domain_fd = create_domain_with_features(kvm_fd, cross_vm ? 2 : 1, 1,
						features,
						&domain_generation);
	attach_vcpu(domain_fd, a->fd, 51, 1);
	if (cross_vm)
		attach_vcpu(domain_fd, b->fd, 52, 1);
	run_arg.executor_fd = create_executor(domain_fd, 1,
					      &executor_generation);
	run_arg.trace = (struct kvm_exec_run_trace) {
		.size = sizeof(run_arg.trace),
		.request_sequence = 1,
		.domain_generation = domain_generation,
		.executor_generation = executor_generation,
		.entries = (uintptr_t)entries,
		.nr_entries = cross_vm ? ARRAY_SIZE(entries) : 1,
		.repeat_count = KVM_EXEC_TRACE_MAX_STEPS /
				(cross_vm ? ARRAY_SIZE(entries) : 1),
	};

	TEST_ASSERT(!pthread_create(&thread, NULL, trace_runner, &run_arg),
		    "pthread_create failed");
	for (i = 0; i < 1000000 &&
	     (vcpu_get_stat(stats_fds[0], "exits") == exits_before[0] ||
	      (cross_vm && vcpu_get_stat(stats_fds[1], "exits") ==
	       exits_before[1])); i++)
		sched_yield();
	TEST_ASSERT(vcpu_get_stat(stats_fds[0], "exits") > exits_before[0] &&
		    (!cross_vm ||
		     vcpu_get_stat(stats_fds[1], "exits") > exits_before[1]),
		    "signal trace did not start every target");
	assert_ioctl_errno(domain_fd, KVM_EXEC_DETACH_VCPU, &detach[0], EBUSY);
	if (cross_vm)
		assert_ioctl_errno(domain_fd, KVM_EXEC_DETACH_VCPU, &detach[1],
				   EBUSY);
	TEST_ASSERT(!pthread_kill(thread, SIGUSR1), "pthread_kill failed");
	pthread_join(thread, NULL);
	TEST_ASSERT(!run_arg.ret,
		    "signaled trace returned %d errno %d", run_arg.ret,
		    run_arg.error);
	TEST_ASSERT_EQ(run_arg.trace.return_reason, KVM_EXEC_RETURN_SIGNAL);
	TEST_ASSERT_EQ(run_arg.trace.run_result, -EINTR);
	TEST_ASSERT(run_arg.trace.completed_steps < KVM_EXEC_TRACE_MAX_STEPS,
		    "signal did not stop the trace before its step bound");
	if (cross_vm)
		TEST_ASSERT(run_arg.trace.switch_count > 0,
			    "cross-VM signal test did not switch targets");

	close(run_arg.executor_fd);
	detach_vcpu(domain_fd, 51, 1);
	if (cross_vm)
		detach_vcpu(domain_fd, 52, 1);
	close(domain_fd);
	close(stats_fds[0]);
	if (vm_b) {
		close(stats_fds[1]);
		kvm_vm_free(vm_b);
	}
	kvm_vm_free(vm_a);
}

static void test_halted_trace_pause_and_drain(int kvm_fd)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN;
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	struct kvm_exec_trace_entry entry = {
		.capsule_id = 22,
		.lifecycle_generation = 1,
	};
	struct trace_run_arg run_arg = { };
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint64_t domain_generation, executor_generation;
	uint64_t *ready;
	pthread_t thread;
	int domain_fd, i;

	vm = vm_create_with_one_vcpu(&vcpu, guest_trace_hlt);
	disable_nested_cpuid(vcpu);
	vcpu_guest_debug_set(vcpu, &debug);
	ready = addr_gva2hva(vm, (vm_vaddr_t)&trace_hlt_ready);
	WRITE_ONCE(*ready, 0);
	domain_fd = create_domain_with_features(kvm_fd, 1, 1, features,
						&domain_generation);
	attach_vcpu(domain_fd, vcpu->fd, 22, 1);
	run_arg.executor_fd = create_executor(domain_fd, 1,
					      &executor_generation);
	run_arg.trace = (struct kvm_exec_run_trace) {
		.size = sizeof(run_arg.trace),
		.request_sequence = 1,
		.domain_generation = domain_generation,
		.executor_generation = executor_generation,
		.entries = (uintptr_t)&entry,
		.nr_entries = 1,
		.repeat_count = KVM_EXEC_TRACE_MAX_STEPS,
	};
	TEST_ASSERT(!pthread_create(&thread, NULL, trace_runner, &run_arg),
		    "pthread_create failed");
	for (i = 0; i < 1000000 && !READ_ONCE(*ready); i++)
		sched_yield();
	TEST_ASSERT(READ_ONCE(*ready), "trace guest did not reach HLT setup");
	usleep(1000);

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	pthread_join(thread, NULL);
	TEST_ASSERT(!run_arg.ret,
		    "halted trace returned %d errno %d", run_arg.ret,
		    run_arg.error);
	TEST_ASSERT_EQ(run_arg.trace.return_reason,
		       KVM_EXEC_RETURN_DOMAIN_PAUSED);
	TEST_ASSERT(run_arg.trace.completed_steps > 0 &&
		    run_arg.trace.completed_steps < KVM_EXEC_TRACE_MAX_STEPS,
		    "halted trace did not stop at a bounded step");
	TEST_ASSERT_EQ(run_arg.trace.owned_capsule_id, 22);

	detach_vcpu(domain_fd, 22, 1);
	close(run_arg.executor_fd);
	close(domain_fd);
	kvm_vm_free(vm);
}

static void test_create_empty_domain(int kvm_fd)
{
	uint64_t generation;
	int domain_fd = create_domain(kvm_fd, 4, 2, &generation);

	close(domain_fd);
}

static void test_one_capsule_run_and_legacy_restore(int kvm_fd)
{
	struct kvm_exec_detach_vcpu detach = {
		.size = sizeof(detach),
		.capsule_id = 1,
		.lifecycle_generation = 1,
	};
	struct kvm_exec_run run;
	struct kvm_interrupt irq = { .irq = 32 };
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint64_t domain_generation, executor_generation;
	int domain_fd, executor_fd, ret;

	vm = vm_create_with_one_vcpu(&vcpu, guest_two_exits);
	disable_nested_cpuid(vcpu);
	domain_fd = create_domain(kvm_fd, 2, 1, &domain_generation);
	attach_vcpu(domain_fd, vcpu->fd, 1, 1);

	assert_ioctl_errno(vcpu->fd, KVM_RUN, NULL, EBUSY);
	executor_fd = create_executor(domain_fd, 0x11, &executor_generation);

	memset(&run, 0, sizeof(run));
	run.size = sizeof(run);
	run.request_sequence = 1;
	run.domain_generation = domain_generation;
	run.executor_generation = executor_generation;
	run.target_capsule_id = 1;
	run.target_lifecycle_generation = 1;
	run.user_cookie = 0x1234;
	ret = ioctl(executor_fd, KVM_EXEC_RUN, &run);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN, ret));
	TEST_ASSERT_EQ(run.return_reason, KVM_EXEC_RETURN_VCPU_EXIT);
	TEST_ASSERT_EQ(run.run_result, 0);
	TEST_ASSERT_EQ(run.vcpu_exit_reason, KVM_EXIT_IO);
	TEST_ASSERT_EQ(run.owned_capsule_id, 1);
	TEST_ASSERT_EQ(run.owned_lifecycle_generation, 1);

	/*
	 * The selftest library creates an in-kernel PIC, for which x86 KVM
	 * rejects KVM_INTERRUPT with ENXIO.  Reaching that error instead of the
	 * execution-domain EBUSY proves that injection is allowed at this
	 * returned executor boundary.
	 */
	assert_ioctl_errno(vcpu->fd, KVM_INTERRUPT, &irq, ENXIO);

	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN, &run, ESTALE);
	assert_ioctl_errno(domain_fd, KVM_EXEC_DETACH_VCPU, &detach, EBUSY);
	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	detach_vcpu(domain_fd, 1, 1);
	control_domain(domain_fd, KVM_EXEC_RESUME);

	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);

	close(executor_fd);
	close(domain_fd);
	kvm_vm_free(vm);
}

static void test_strict_cpu_placement(int kvm_fd)
{
	struct kvm_exec_run run = { .size = sizeof(run) };
	uint64_t domain_generation, executor_generation;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	cpu_set_t original_mask, pinned_mask;
	long configured_cpus;
	int correct_executor_fd, wrong_executor_fd;
	int domain_fd, correct_cpu, wrong_cpu, ret;

	TEST_ASSERT(!sched_getaffinity(0, sizeof(original_mask), &original_mask),
		    "sched_getaffinity failed, errno %d", errno);
	correct_cpu = CPU_SETSIZE;
	for (ret = 0; ret < CPU_SETSIZE; ret++) {
		if (CPU_ISSET(ret, &original_mask)) {
			correct_cpu = ret;
			break;
		}
	}
	TEST_ASSERT(correct_cpu < CPU_SETSIZE, "empty CPU affinity mask");
	CPU_ZERO(&pinned_mask);
	CPU_SET(correct_cpu, &pinned_mask);
	TEST_ASSERT(!sched_setaffinity(0, sizeof(pinned_mask), &pinned_mask),
		    "sched_setaffinity failed, errno %d", errno);
	TEST_ASSERT_EQ(sched_getcpu(), correct_cpu);

	configured_cpus = sysconf(_SC_NPROCESSORS_CONF);
	TEST_ASSERT(configured_cpus > 1 && configured_cpus <= CPU_SETSIZE,
		    "strict placement test needs at least two configured CPUs");
	wrong_cpu = (correct_cpu + 1) % configured_cpus;

	vm = vm_create_with_one_vcpu(&vcpu, guest_two_exits);
	disable_nested_cpuid(vcpu);
	domain_fd = create_domain(kvm_fd, 1, 2, &domain_generation);
	attach_vcpu(domain_fd, vcpu->fd, 1, 1);

	wrong_executor_fd = create_executor_on_cpu(domain_fd, 1,
						   KVM_EXECUTOR_F_STRICT_CPU,
						   wrong_cpu, &executor_generation);
	run.request_sequence = 1;
	run.domain_generation = domain_generation;
	run.executor_generation = executor_generation;
	run.target_capsule_id = 1;
	run.target_lifecycle_generation = 1;
	assert_ioctl_errno(wrong_executor_fd, KVM_EXEC_RUN, &run, EXDEV);

	correct_executor_fd = create_executor_on_cpu(domain_fd, 2,
						     KVM_EXECUTOR_F_STRICT_CPU,
						     correct_cpu, &executor_generation);
	run.executor_generation = executor_generation;
	ret = ioctl(correct_executor_fd, KVM_EXEC_RUN, &run);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN, ret));
	TEST_ASSERT_EQ(run.return_reason, KVM_EXEC_RETURN_VCPU_EXIT);
	TEST_ASSERT_EQ(run.vcpu_exit_reason, KVM_EXIT_IO);
	TEST_ASSERT_EQ(run.current_cpu, correct_cpu);

	close(correct_executor_fd);
	close(wrong_executor_fd);
	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	detach_vcpu(domain_fd, 1, 1);
	close(domain_fd);
	kvm_vm_free(vm);
	TEST_ASSERT(!sched_setaffinity(0, sizeof(original_mask), &original_mask),
		    "failed to restore CPU affinity, errno %d", errno);
}

static void test_rejects_unsupported_x86_state(int kvm_fd)
{
	struct kvm_exec_attach_vcpu attach = {
		.size = sizeof(attach),
		.capsule_id = 1,
		.lifecycle_generation = 1,
	};
	struct kvm_vcpu_events events;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint64_t domain_generation;
	bool nested_exposed;
	int domain_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_two_exits);
	domain_fd = create_domain(kvm_fd, 1, 1, &domain_generation);
	attach.vcpu_fd = vcpu->fd;

	nested_exposed = kvm_cpu_has(X86_FEATURE_VMX) ||
			 kvm_cpu_has(X86_FEATURE_SVM);
	if (nested_exposed)
		assert_ioctl_errno(domain_fd, KVM_EXEC_ATTACH_VCPU, &attach,
				   EOPNOTSUPP);
	disable_nested_cpuid(vcpu);

	if (ioctl(kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_X86_SMM)) {
		vcpu_events_get(vcpu, &events);
		events.flags |= KVM_VCPUEVENT_VALID_SMM;
		events.smi.smm = 1;
		vcpu_events_set(vcpu, &events);
		assert_ioctl_errno(domain_fd, KVM_EXEC_ATTACH_VCPU, &attach,
				   EOPNOTSUPP);

		events.smi.smm = 0;
		vcpu_events_set(vcpu, &events);
	}

	attach_vcpu(domain_fd, vcpu->fd, 1, 1);
	detach_vcpu(domain_fd, 1, 1);
	close(domain_fd);
	kvm_vm_free(vm);
}

static void test_many_capsules_across_vms(int kvm_fd)
{
	struct kvm_vcpu *a0, *a1, *b0;
	struct kvm_vm *vm_a, *vm_b;
	uint64_t generation;
	int domain_fd;

	vm_a = vm_create_with_one_vcpu(&a0, guest_two_exits);
	a1 = vm_vcpu_add(vm_a, 1, guest_two_exits);
	vm_b = vm_create_with_one_vcpu(&b0, guest_two_exits);
	disable_nested_cpuid(a0);
	disable_nested_cpuid(a1);
	disable_nested_cpuid(b0);

	domain_fd = create_domain(kvm_fd, 3, 1, &generation);
	attach_vcpu(domain_fd, a0->fd, 1, 1);
	attach_vcpu(domain_fd, a1->fd, 2, 1);
	attach_vcpu(domain_fd, b0->fd, 3, 1);
	detach_vcpu(domain_fd, 2, 1);
	detach_vcpu(domain_fd, 1, 1);
	detach_vcpu(domain_fd, 3, 1);

	close(domain_fd);
	kvm_vm_free(vm_b);
	kvm_vm_free(vm_a);
}

struct race_arg {
	pthread_barrier_t *barrier;
	struct kvm_exec_run run;
	int executor_fd;
	int ret;
	int error;
};

static void *race_executor(void *opaque)
{
	struct race_arg *arg = opaque;

	pthread_barrier_wait(arg->barrier);
	errno = 0;
	arg->ret = ioctl(arg->executor_fd, KVM_EXEC_RUN, &arg->run);
	arg->error = errno;
	return NULL;
}

static void test_two_executor_claim_race(int kvm_fd)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct race_arg args[2];
	pthread_barrier_t barrier;
	pthread_t threads[2];
	uint64_t domain_generation, executor_generation[2];
	int domain_fd, successes = 0, busy = 0;
	int i;

	vm = vm_create_with_one_vcpu(&vcpu, guest_two_exits);
	disable_nested_cpuid(vcpu);
	domain_fd = create_domain(kvm_fd, 1, 2, &domain_generation);
	attach_vcpu(domain_fd, vcpu->fd, 7, 3);
	memset(args, 0, sizeof(args));
	pthread_barrier_init(&barrier, NULL, 3);
	for (i = 0; i < 2; i++) {
		args[i].barrier = &barrier;
		args[i].executor_fd =
			create_executor(domain_fd, i, &executor_generation[i]);
		args[i].run.size = sizeof(args[i].run);
		args[i].run.request_sequence = 1;
		args[i].run.domain_generation = domain_generation;
		args[i].run.executor_generation = executor_generation[i];
		args[i].run.target_capsule_id = 7;
		args[i].run.target_lifecycle_generation = 3;
		TEST_ASSERT(!pthread_create(&threads[i], NULL, race_executor,
					    &args[i]),
			    "pthread_create failed");
	}
	pthread_barrier_wait(&barrier);
	for (i = 0; i < 2; i++) {
		pthread_join(threads[i], NULL);
		if (!args[i].ret)
			successes++;
		else if (args[i].ret == -1 && args[i].error == EBUSY)
			busy++;
	}
	TEST_ASSERT(successes == 1 && busy == 1,
		    "claim race produced %d successes and %d EBUSY results",
		    successes, busy);

	for (i = 0; i < 2; i++)
		close(args[i].executor_fd);
	pthread_barrier_destroy(&barrier);
	detach_vcpu(domain_fd, 7, 3);
	close(domain_fd);
	kvm_vm_free(vm);
}

static uint64_t guest_started;

static void guest_spin(void)
{
	WRITE_ONCE(guest_started, 1);
	for (;;)
		asm volatile("pause");
}

static void guest_spin_irqs_disabled(void)
{
	asm volatile("cli" ::: "memory");
	guest_spin();
}

static uint64_t *guest_started_hva(struct kvm_vm *vm)
{
	uint64_t *started =
		addr_gva2hva(vm, (vm_vaddr_t)&guest_started);

	WRITE_ONCE(*started, 0);
	return started;
}

static void wait_for_guest(uint64_t *started)
{
	int i;

	for (i = 0; i < 1000000 && !READ_ONCE(*started); i++)
		sched_yield();
	TEST_ASSERT(READ_ONCE(*started), "guest did not enter its spin loop");
}

static void wait_for_trace_progress(uint64_t *count, uint64_t previous)
{
	int i;

	for (i = 0; i < 1000000 && READ_ONCE(*count) == previous; i++)
		sched_yield();
	TEST_ASSERT(READ_ONCE(*count) > previous,
		    "dispatched capsule did not make guest progress");
}

static void signal_handler(int signal)
{
}

struct vcpu_run_arg {
	struct kvm_vcpu *vcpu;
	int ret;
	int error;
};

static void *ordinary_vcpu_runner(void *opaque)
{
	struct vcpu_run_arg *arg = opaque;

	errno = 0;
	arg->ret = __vcpu_run(arg->vcpu);
	arg->error = errno;
	return NULL;
}

static void test_attach_rejects_active_kvm_run(int kvm_fd)
{
	struct kvm_exec_attach_vcpu attach = {
		.size = sizeof(attach),
		.capsule_id = 1,
		.lifecycle_generation = 1,
	};
	struct vcpu_run_arg run_arg = { };
	uint64_t *started;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	pthread_t thread;
	uint64_t generation;
	int domain_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_spin);
	disable_nested_cpuid(vcpu);
	started = guest_started_hva(vm);
	domain_fd = create_domain(kvm_fd, 1, 1, &generation);
	attach.vcpu_fd = vcpu->fd;
	run_arg.vcpu = vcpu;
	TEST_ASSERT(!pthread_create(&thread, NULL, ordinary_vcpu_runner,
				    &run_arg),
		    "pthread_create failed");
	wait_for_guest(started);
	assert_ioctl_errno(domain_fd, KVM_EXEC_ATTACH_VCPU, &attach, EBUSY);
	TEST_ASSERT(!pthread_kill(thread, SIGUSR1), "pthread_kill failed");
	pthread_join(thread, NULL);
	TEST_ASSERT(run_arg.ret == -1 && run_arg.error == EINTR,
		    "ordinary KVM_RUN did not return EINTR after signal");

	attach_vcpu(domain_fd, vcpu->fd, 1, 1);
	detach_vcpu(domain_fd, 1, 1);
	close(domain_fd);
	kvm_vm_free(vm);
}

struct executor_run_arg {
	struct kvm_exec_run run;
	int executor_fd;
	int ret;
	int error;
};

static void *executor_runner(void *opaque)
{
	struct executor_run_arg *arg = opaque;

	errno = 0;
	arg->ret = ioctl(arg->executor_fd, KVM_EXEC_RUN, &arg->run);
	arg->error = errno;
	return NULL;
}

struct dispatch_mapping {
	struct kvm_exec_dispatch_header *header;
	struct kvm_exec_command *commands;
	struct kvm_exec_completion *completions;
};

struct dispatch_run_arg {
	struct kvm_exec_run_dispatch run;
	int executor_fd;
	int ret;
	int error;
};

static struct dispatch_mapping map_dispatch(int executor_fd)
{
	struct dispatch_mapping mapping;
	void *region;

	region = mmap(NULL, KVM_EXEC_DISPATCH_MMAP_SIZE,
		      PROT_READ | PROT_WRITE, MAP_SHARED, executor_fd, 0);
	TEST_ASSERT(region != MAP_FAILED, "executor mmap failed, errno: %d", errno);
	mapping.header = region;
	mapping.commands = region + KVM_EXEC_DISPATCH_COMMAND_OFFSET;
	mapping.completions = region + KVM_EXEC_DISPATCH_COMPLETION_OFFSET;
	return mapping;
}

static bool publish_dispatch_command(struct dispatch_mapping *mapping,
				     struct kvm_exec_command command)
{
	uint64_t head = __atomic_load_n(&mapping->header->command_head,
					__ATOMIC_ACQUIRE);
	uint64_t tail = mapping->header->command_tail;

	if (tail - head == KVM_EXEC_DISPATCH_RING_ENTRIES)
		return false;
	command.size = sizeof(command);
	mapping->commands[tail % KVM_EXEC_DISPATCH_RING_ENTRIES] = command;
	__atomic_store_n(&mapping->header->command_tail, tail + 1,
			 __ATOMIC_RELEASE);
	return true;
}

static struct kvm_exec_completion
consume_dispatch_completion(struct dispatch_mapping *mapping)
{
	struct kvm_exec_completion completion;
	struct timespec now, deadline;
	uint64_t head;

	TEST_ASSERT(!clock_gettime(CLOCK_MONOTONIC, &now),
		    "clock_gettime failed, errno: %d", errno);
	deadline = timespec_add_ns(now, 10ULL * NSEC_PER_SEC);
	for (;;) {
		head = mapping->header->completion_head;
		if (__atomic_load_n(&mapping->header->completion_tail,
				    __ATOMIC_ACQUIRE) != head)
			break;
		TEST_ASSERT(!clock_gettime(CLOCK_MONOTONIC, &now),
			    "clock_gettime failed, errno: %d", errno);
		TEST_ASSERT(timespec_to_ns(timespec_sub(deadline, now)) > 0,
			    "timed out waiting for dispatch completion: command=%llu/%llu completion=%llu/%llu kick=%llu consumed=%llu applied=%llu entry=%llu",
			    (unsigned long long)mapping->header->command_head,
			    (unsigned long long)mapping->header->command_tail,
			    (unsigned long long)head,
			    (unsigned long long)mapping->header->completion_tail,
			    (unsigned long long)mapping->header->last_kick_sequence,
			    (unsigned long long)mapping->header->last_consumed_sequence,
			    (unsigned long long)mapping->header->last_applied_sequence,
			    (unsigned long long)mapping->header->last_entry_sequence);
		sched_yield();
	}
	completion = mapping->completions[head % KVM_EXEC_DISPATCH_RING_ENTRIES];
	__atomic_store_n(&mapping->header->completion_head, head + 1,
			 __ATOMIC_RELEASE);
	return completion;
}

static void kick_dispatch(int executor_fd, uint64_t domain_generation,
			  uint64_t executor_generation, uint64_t sequence)
{
	struct kvm_exec_kick kick = {
		.size = sizeof(kick),
		.domain_generation = domain_generation,
		.executor_generation = executor_generation,
		.request_sequence = sequence,
	};
	int ret = ioctl(executor_fd, KVM_EXEC_KICK, &kick);

	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_KICK, ret));
}

static uint32_t cancel_dispatch(int executor_fd, uint64_t domain_generation,
				uint64_t executor_generation, uint64_t sequence)
{
	struct kvm_exec_cancel cancel = {
		.size = sizeof(cancel),
		.domain_generation = domain_generation,
		.executor_generation = executor_generation,
		.request_sequence = sequence,
	};
	int ret = ioctl(executor_fd, KVM_EXEC_CANCEL, &cancel);

	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_CANCEL, ret));
	return cancel.status;
}

static void *dispatch_runner(void *opaque)
{
	struct dispatch_run_arg *arg = opaque;

	errno = 0;
	arg->ret = ioctl(arg->executor_fd, KVM_EXEC_RUN_DISPATCH, &arg->run);
	arg->error = errno;
	return NULL;
}

#define SYNC_EXIT_PIO_PORT 0xe8

static uint64_t sync_exit_pio_value;
static uint64_t sync_exit_pio_progress;
static uint64_t sync_exit_mmio_value;
static uint64_t sync_exit_mmio_progress;

static void guest_sync_pio(void)
{
	uint32_t value;

	asm volatile("inl %w1, %0"
		     : "=a" (value)
		     : "d" (SYNC_EXIT_PIO_PORT));
	WRITE_ONCE(sync_exit_pio_value, value);
	WRITE_ONCE(sync_exit_pio_progress, 1);
	asm volatile("outl %0, %w1"
		     :
		     : "a" (value), "d" (SYNC_EXIT_PIO_PORT));
	WRITE_ONCE(sync_exit_pio_progress, 2);
	asm volatile("hlt");
}

static void guest_sync_mmio(void)
{
	uint64_t value = READ_ONCE(*(uint64_t *)TRACE_MMIO_GPA);

	WRITE_ONCE(sync_exit_mmio_value, value);
	WRITE_ONCE(sync_exit_mmio_progress, 1);
	WRITE_ONCE(*(uint64_t *)(TRACE_MMIO_GPA + 8), ~value);
	WRITE_ONCE(sync_exit_mmio_progress, 2);
	asm volatile("hlt");
}

static struct kvm_exec_run_dispatch
run_dispatch_once(int executor_fd, uint64_t domain_generation,
		  uint64_t executor_generation)
{
	struct kvm_exec_run_dispatch run = {
		.size = sizeof(run),
		.flags = KVM_EXEC_DISPATCH_F_RETURN_IF_EMPTY,
		.domain_generation = domain_generation,
		.executor_generation = executor_generation,
	};
	int ret = ioctl(executor_fd, KVM_EXEC_RUN_DISPATCH, &run);

	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN_DISPATCH, ret));
	return run;
}

static void test_dynamic_synchronous_exits(int kvm_fd)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN |
				  KVM_EXEC_FEATURE_CROSS_VM_CHAIN |
				  KVM_EXEC_FEATURE_DYNAMIC_DISPATCH |
				  KVM_EXEC_FEATURE_SYNC_EXITS;
	struct kvm_exec_command command = {
		.opcode = KVM_EXEC_CMD_SWITCH,
		.request_sequence = 1,
		.target_capsule_id = 61,
		.target_lifecycle_generation = 16,
	};
	struct kvm_exec_domain_control control = { .size = sizeof(control) };
	struct kvm_exec_trace_entry legacy_entry = {
		.capsule_id = 61,
		.lifecycle_generation = 16,
	};
	struct kvm_exec_run legacy_run = {
		.size = sizeof(legacy_run),
		.request_sequence = 1,
		.target_capsule_id = 61,
		.target_lifecycle_generation = 16,
	};
	struct kvm_exec_run_trace legacy_trace = {
		.size = sizeof(legacy_trace),
		.request_sequence = 1,
		.entries = (uintptr_t)&legacy_entry,
		.nr_entries = 1,
		.repeat_count = 1,
	};
	struct kvm_exec_run_dispatch run;
	struct kvm_exec_completion completion;
	struct dispatch_mapping mapping;
	struct kvm_signal_mask *kvm_sigmask;
	struct kvm_regs saved_regs;
	struct kvm_vcpu *pio_vcpu, *mmio_vcpu;
	struct kvm_vm *pio_vm, *mmio_vm;
	sigset_t blocked_mask, original_mask;
	uint64_t *pio_value, *pio_progress, *mmio_value, *mmio_progress;
	uint64_t domain_generation, executor_generation;
	uint32_t pio_response = 0xa55ac33c;
	uint64_t mmio_response = 0xfedcba9876543210ULL;
	uint16_t saved_port;
	uint32_t saved_mmio_len;
	int domain_fd, executor_fd, received_signal;

	pio_vm = vm_create_with_one_vcpu(&pio_vcpu, guest_sync_pio);
	mmio_vm = vm_create_with_one_vcpu(&mmio_vcpu, guest_sync_mmio);
	disable_nested_cpuid(pio_vcpu);
	disable_nested_cpuid(mmio_vcpu);
	vcpu_regs_get(pio_vcpu, &saved_regs);
	sigemptyset(&blocked_mask);
	sigaddset(&blocked_mask, SIGUSR1);
	TEST_ASSERT(!pthread_sigmask(SIG_BLOCK, &blocked_mask, &original_mask),
		    "blocking synchronous-exit signal failed");
	kvm_sigmask = alloca(offsetof(struct kvm_signal_mask, sigset) +
			     sizeof(sigset_t));
	kvm_sigmask->len = 8;
	TEST_ASSERT(!pthread_sigmask(0, NULL,
				     (sigset_t *)kvm_sigmask->sigset),
		    "reading synchronous-exit signal mask failed");
	sigdelset((sigset_t *)kvm_sigmask->sigset, SIGUSR1);
	vcpu_ioctl(pio_vcpu, KVM_SET_SIGNAL_MASK, kvm_sigmask);
	virt_map(mmio_vm, TRACE_MMIO_GPA, TRACE_MMIO_GPA, 1);
	pio_value = addr_gva2hva(pio_vm, (vm_vaddr_t)&sync_exit_pio_value);
	pio_progress = addr_gva2hva(pio_vm,
				    (vm_vaddr_t)&sync_exit_pio_progress);
	mmio_value = addr_gva2hva(mmio_vm,
				  (vm_vaddr_t)&sync_exit_mmio_value);
	mmio_progress = addr_gva2hva(mmio_vm,
				     (vm_vaddr_t)&sync_exit_mmio_progress);
	WRITE_ONCE(*pio_progress, 0);
	WRITE_ONCE(*mmio_progress, 0);

	domain_fd = create_domain_with_features(kvm_fd, 2, 1, features,
						&domain_generation);
	attach_vcpu(domain_fd, pio_vcpu->fd, 61, 16);
	attach_vcpu(domain_fd, mmio_vcpu->fd, 62, 26);
	executor_fd = create_executor(domain_fd, 0x708, &executor_generation);
	legacy_run.domain_generation = domain_generation;
	legacy_run.executor_generation = executor_generation;
	legacy_trace.domain_generation = domain_generation;
	legacy_trace.executor_generation = executor_generation;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN, &legacy_run,
			   EOPNOTSUPP);
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN_TRACE, &legacy_trace,
			   EOPNOTSUPP);
	mapping = map_dispatch(executor_fd);
	command.domain_generation = domain_generation;
	command.executor_generation = executor_generation;
	TEST_ASSERT(publish_dispatch_command(&mapping, command),
		    "initial synchronous-exit command did not publish");

	run = run_dispatch_once(executor_fd, domain_generation,
				executor_generation);
	completion = consume_dispatch_completion(&mapping);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_APPLIED);
	TEST_ASSERT_EQ(run.return_reason, KVM_EXEC_RETURN_VCPU_EXIT);
	TEST_ASSERT_EQ(run.vcpu_exit_reason, KVM_EXIT_IO);
	TEST_ASSERT_EQ(run.exit_sequence, 1);
	TEST_ASSERT_EQ(run.exit_flags,
		       KVM_EXEC_EXIT_F_COMPLETION_PENDING);
	TEST_ASSERT_EQ(run.owned_capsule_id, 61);
	TEST_ASSERT_EQ(READ_ONCE(*pio_progress), 0);

	/* Immutable exit metadata must be restored before KVM will reenter. */
	saved_port = pio_vcpu->run->io.port;
	pio_vcpu->run->io.port++;
	run = run_dispatch_once(executor_fd, domain_generation,
				executor_generation);
	TEST_ASSERT_EQ(run.return_reason,
		       KVM_EXEC_RETURN_INVALID_COMPLETION);
	TEST_ASSERT_EQ(run.run_result, -EINVAL);
	TEST_ASSERT_EQ(run.exit_sequence, 1);
	TEST_ASSERT_EQ(run.exit_flags,
		       KVM_EXEC_EXIT_F_COMPLETION_PENDING);
	TEST_ASSERT_EQ(READ_ONCE(*pio_progress), 0);
	pio_vcpu->run->io.port = saved_port;

	/* Pause cannot discard an instruction that still needs completion. */
	control_domain(domain_fd, KVM_EXEC_PAUSE);
	assert_ioctl_errno(domain_fd, KVM_EXEC_DRAIN, &control, EBUSY);
	assert_ioctl_errno(pio_vcpu->fd, KVM_SET_REGS, &saved_regs, EBUSY);
	control_domain(domain_fd, KVM_EXEC_RESUME);

	memcpy((uint8_t *)pio_vcpu->run + pio_vcpu->run->io.data_offset,
	       &pio_response, sizeof(pio_response));
	TEST_ASSERT(!pthread_kill(pthread_self(), SIGUSR1),
		    "queuing synchronous-exit signal failed");
	run = run_dispatch_once(executor_fd, domain_generation,
				executor_generation);
	TEST_ASSERT_EQ(run.return_reason, KVM_EXEC_RETURN_SIGNAL);
	TEST_ASSERT_EQ(run.run_result, -EINTR);
	TEST_ASSERT_EQ(run.owned_capsule_id, 61);
	TEST_ASSERT_EQ(run.exit_sequence, 1);
	TEST_ASSERT_EQ(run.exit_flags, 0);
	TEST_ASSERT_EQ(READ_ONCE(*pio_progress), 0);
	TEST_ASSERT(!sigwait(&blocked_mask, &received_signal),
		    "consuming synchronous-exit signal failed");
	TEST_ASSERT_EQ(received_signal, SIGUSR1);

	run = run_dispatch_once(executor_fd, domain_generation,
				executor_generation);
	TEST_ASSERT_EQ(run.vcpu_exit_reason, KVM_EXIT_IO);
	TEST_ASSERT_EQ(run.exit_sequence, 2);
	TEST_ASSERT_EQ(run.exit_flags,
		       KVM_EXEC_EXIT_F_COMPLETION_PENDING);
	TEST_ASSERT_EQ(READ_ONCE(*pio_value), pio_response);
	TEST_ASSERT_EQ(READ_ONCE(*pio_progress), 1);
	control_domain(domain_fd, KVM_EXEC_PAUSE);
	assert_ioctl_errno(domain_fd, KVM_EXEC_DRAIN, &control, EBUSY);
	control_domain(domain_fd, KVM_EXEC_RESUME);

	/* A command may arrive, but ownership cannot change before reentry. */
	command = (struct kvm_exec_command) {
		.opcode = KVM_EXEC_CMD_RELEASE,
		.request_sequence = 2,
		.domain_generation = domain_generation,
		.executor_generation = executor_generation,
		.expected_current_id = 61,
		.expected_current_generation = 16,
	};
	TEST_ASSERT(publish_dispatch_command(&mapping, command),
		    "pending-exit release did not publish");
	run = run_dispatch_once(executor_fd, domain_generation,
				executor_generation);
	completion = consume_dispatch_completion(&mapping);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_EXIT_PENDING);
	TEST_ASSERT_EQ(completion.owned_capsule_id, 61);
	TEST_ASSERT_EQ(run.vcpu_exit_reason, KVM_EXIT_HLT);
	TEST_ASSERT_EQ(run.exit_sequence, 3);
	TEST_ASSERT_EQ(run.exit_flags, 0);
	TEST_ASSERT_EQ(READ_ONCE(*pio_progress), 2);

	command = (struct kvm_exec_command) {
		.opcode = KVM_EXEC_CMD_SWITCH,
		.request_sequence = 3,
		.domain_generation = domain_generation,
		.executor_generation = executor_generation,
		.expected_current_id = 61,
		.expected_current_generation = 16,
		.target_capsule_id = 62,
		.target_lifecycle_generation = 26,
	};
	TEST_ASSERT(publish_dispatch_command(&mapping, command),
		    "MMIO capsule command did not publish");
	run = run_dispatch_once(executor_fd, domain_generation,
				executor_generation);
	completion = consume_dispatch_completion(&mapping);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_APPLIED);
	TEST_ASSERT_EQ(run.vcpu_exit_reason, KVM_EXIT_MMIO);
	TEST_ASSERT_EQ(run.owned_capsule_id, 62);
	TEST_ASSERT_EQ(run.exit_sequence, 1);
	TEST_ASSERT_EQ(run.exit_flags,
		       KVM_EXEC_EXIT_F_COMPLETION_PENDING);

	saved_mmio_len = mmio_vcpu->run->mmio.len;
	mmio_vcpu->run->mmio.len = 0;
	run = run_dispatch_once(executor_fd, domain_generation,
				executor_generation);
	TEST_ASSERT_EQ(run.return_reason,
		       KVM_EXEC_RETURN_INVALID_COMPLETION);
	TEST_ASSERT_EQ(run.exit_sequence, 1);
	TEST_ASSERT_EQ(READ_ONCE(*mmio_progress), 0);
	mmio_vcpu->run->mmio.len = saved_mmio_len;
	memcpy(mmio_vcpu->run->mmio.data, &mmio_response,
	       sizeof(mmio_response));

	run = run_dispatch_once(executor_fd, domain_generation,
				executor_generation);
	TEST_ASSERT_EQ(run.vcpu_exit_reason, KVM_EXIT_MMIO);
	TEST_ASSERT_EQ(run.exit_sequence, 2);
	TEST_ASSERT_EQ(run.exit_flags,
		       KVM_EXEC_EXIT_F_COMPLETION_PENDING);
	TEST_ASSERT_EQ(READ_ONCE(*mmio_value), mmio_response);
	TEST_ASSERT_EQ(READ_ONCE(*mmio_progress), 1);
	run = run_dispatch_once(executor_fd, domain_generation,
				executor_generation);
	TEST_ASSERT_EQ(run.vcpu_exit_reason, KVM_EXIT_HLT);
	TEST_ASSERT_EQ(run.exit_sequence, 3);
	TEST_ASSERT_EQ(run.exit_flags, 0);
	TEST_ASSERT_EQ(READ_ONCE(*mmio_progress), 2);

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	detach_vcpu(domain_fd, 61, 16);
	detach_vcpu(domain_fd, 62, 26);
	munmap(mapping.header, KVM_EXEC_DISPATCH_MMAP_SIZE);
	close(executor_fd);
	close(domain_fd);
	kvm_vm_free(mmio_vm);
	kvm_vm_free(pio_vm);
	TEST_ASSERT(!pthread_sigmask(SIG_SETMASK, &original_mask, NULL),
		    "restoring synchronous-exit signal mask failed");
}

static void test_sync_domain_close_pending(int kvm_fd, bool close_on_write)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_DYNAMIC_DISPATCH |
				  KVM_EXEC_FEATURE_SYNC_EXITS;
	struct kvm_exec_command command = {
		.opcode = KVM_EXEC_CMD_SWITCH,
		.request_sequence = 1,
		.target_capsule_id = 63,
		.target_lifecycle_generation = 36,
	};
	struct kvm_exec_detach_vcpu detach = {
		.size = sizeof(detach),
		.capsule_id = 63,
		.lifecycle_generation = 36,
	};
	struct kvm_exec_domain_control control = { .size = sizeof(control) };
	struct kvm_exec_run_dispatch run;
	struct kvm_exec_completion completion;
	struct dispatch_mapping mapping;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint64_t *pio_value, *pio_progress;
	uint64_t domain_generation, executor_generation;
	uint32_t response = 0x13579bdf;
	int domain_fd, executor_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_sync_pio);
	disable_nested_cpuid(vcpu);
	pio_value = addr_gva2hva(vm, (vm_vaddr_t)&sync_exit_pio_value);
	pio_progress = addr_gva2hva(vm,
				    (vm_vaddr_t)&sync_exit_pio_progress);
	WRITE_ONCE(*pio_progress, 0);
	domain_fd = create_domain_with_features(kvm_fd, 1, 1, features,
						&domain_generation);
	attach_vcpu(domain_fd, vcpu->fd, 63, 36);
	executor_fd = create_executor(domain_fd, 0x808,
				      &executor_generation);
	mapping = map_dispatch(executor_fd);
	command.domain_generation = domain_generation;
	command.executor_generation = executor_generation;
	TEST_ASSERT(publish_dispatch_command(&mapping, command),
		    "close-pending command did not publish");
	run = run_dispatch_once(executor_fd, domain_generation,
				executor_generation);
	completion = consume_dispatch_completion(&mapping);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_APPLIED);
	TEST_ASSERT_EQ(run.vcpu_exit_reason, KVM_EXIT_IO);
	TEST_ASSERT_EQ(run.exit_sequence, 1);
	TEST_ASSERT_EQ(run.exit_flags,
		       KVM_EXEC_EXIT_F_COMPLETION_PENDING);

	if (close_on_write) {
		memcpy((uint8_t *)vcpu->run + vcpu->run->io.data_offset,
		       &response, sizeof(response));
		run = run_dispatch_once(executor_fd, domain_generation,
					executor_generation);
		TEST_ASSERT_EQ(run.vcpu_exit_reason, KVM_EXIT_IO);
		TEST_ASSERT_EQ(run.exit_sequence, 2);
		TEST_ASSERT_EQ(run.exit_flags,
			       KVM_EXEC_EXIT_F_COMPLETION_PENDING);
		TEST_ASSERT_EQ(READ_ONCE(*pio_progress), 1);
	}

	munmap(mapping.header, KVM_EXEC_DISPATCH_MMAP_SIZE);
	close(executor_fd);
	control_domain(domain_fd, KVM_EXEC_PAUSE);
	assert_ioctl_errno(domain_fd, KVM_EXEC_DRAIN, &control, EBUSY);
	assert_ioctl_errno(domain_fd, KVM_EXEC_DETACH_VCPU, &detach, EBUSY);
	close(domain_fd);

	if (!close_on_write) {
		memcpy((uint8_t *)vcpu->run + vcpu->run->io.data_offset,
		       &response, sizeof(response));
		vcpu_run(vcpu);
		TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
		TEST_ASSERT_EQ(READ_ONCE(*pio_progress), 1);
	}
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_HLT);
	TEST_ASSERT_EQ(READ_ONCE(*pio_value), response);
	TEST_ASSERT_EQ(READ_ONCE(*pio_progress), 2);
	kvm_vm_free(vm);
}

static void test_dynamic_kick_and_cancel(int kvm_fd)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN |
				  KVM_EXEC_FEATURE_CROSS_VM_CHAIN |
				  KVM_EXEC_FEATURE_DYNAMIC_DISPATCH;
	struct kvm_exec_command command = {
		.opcode = KVM_EXEC_CMD_SWITCH,
		.request_sequence = 1,
		.target_capsule_id = 41,
		.target_lifecycle_generation = 7,
		.user_cookie = 0x701,
	};
	struct dispatch_run_arg run_arg = { };
	struct kvm_exec_cancel stale_cancel = {
		.size = sizeof(stale_cancel),
		.request_sequence = 6,
	};
	struct kvm_exec_completion completion;
	struct dispatch_mapping mapping;
	uint64_t *started;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint64_t domain_generation, executor_generation;
	pthread_t thread;
	int domain_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_spin_irqs_disabled);
	disable_nested_cpuid(vcpu);
	started = guest_started_hva(vm);
	domain_fd = create_domain_with_features(kvm_fd, 1, 1, features,
						&domain_generation);
	attach_vcpu(domain_fd, vcpu->fd, 41, 7);
	run_arg.executor_fd = create_executor(domain_fd, 0x701,
					      &executor_generation);
	mapping = map_dispatch(run_arg.executor_fd);
	command.domain_generation = domain_generation;
	command.executor_generation = executor_generation;
	TEST_ASSERT(publish_dispatch_command(&mapping, command),
		    "initial dispatch command was unexpectedly full");
	run_arg.run.size = sizeof(run_arg.run);
	run_arg.run.domain_generation = domain_generation;
	run_arg.run.executor_generation = executor_generation;
	TEST_ASSERT(!pthread_create(&thread, NULL, dispatch_runner, &run_arg),
		    "pthread_create failed");
	completion = consume_dispatch_completion(&mapping);
	TEST_ASSERT_EQ(completion.request_sequence, 1);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_APPLIED);
	TEST_ASSERT_EQ(completion.previous_capsule_id, 0);
	TEST_ASSERT_EQ(completion.owned_capsule_id, 41);
	TEST_ASSERT(completion.applied_ns && completion.entry_attempt_ns >=
					 completion.applied_ns,
		    "dispatch timestamps are not ordered");
	wait_for_guest(started);

	command = (struct kvm_exec_command) {
		.opcode = KVM_EXEC_CMD_SWITCH,
		.request_sequence = 2,
		.domain_generation = domain_generation,
		.executor_generation = executor_generation,
		.expected_current_id = 41,
		.expected_current_generation = 7,
		.target_capsule_id = 41,
		.target_lifecycle_generation = 8,
	};
	TEST_ASSERT(publish_dispatch_command(&mapping, command),
		    "stale-target command was unexpectedly full");
	kick_dispatch(run_arg.executor_fd, domain_generation,
		      executor_generation, 2);
	completion = consume_dispatch_completion(&mapping);
	TEST_ASSERT_EQ(completion.request_sequence, 2);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_TARGET_STALE);
	TEST_ASSERT_EQ(completion.previous_capsule_id, 41);
	TEST_ASSERT_EQ(completion.owned_capsule_id, 41);

	command = (struct kvm_exec_command) {
		.opcode = KVM_EXEC_CMD_RELEASE,
		.request_sequence = 3,
		.domain_generation = domain_generation,
		.executor_generation = executor_generation,
		.expected_current_id = 41,
		.expected_current_generation = 7,
	};
	TEST_ASSERT(publish_dispatch_command(&mapping, command),
		    "release command was unexpectedly full");
	usleep(20000);
	TEST_ASSERT_EQ(__atomic_load_n(&mapping.header->completion_tail,
				       __ATOMIC_ACQUIRE), 2);
	kick_dispatch(run_arg.executor_fd, domain_generation,
		      executor_generation, 3);
	completion = consume_dispatch_completion(&mapping);
	TEST_ASSERT_EQ(completion.request_sequence, 3);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_RETURNED);
	TEST_ASSERT_EQ(completion.previous_capsule_id, 41);
	TEST_ASSERT_EQ(completion.owned_capsule_id, 0);

	/* A kick before publication cannot make a later command visible. */
	kick_dispatch(run_arg.executor_fd, domain_generation,
		      executor_generation, 4);
	usleep(20000);
	command = (struct kvm_exec_command) {
		.opcode = KVM_EXEC_CMD_SWITCH,
		.request_sequence = 4,
		.domain_generation = domain_generation,
		.executor_generation = executor_generation,
		.target_capsule_id = 41,
		.target_lifecycle_generation = 7,
	};
	TEST_ASSERT(publish_dispatch_command(&mapping, command),
		    "cancelled command was unexpectedly full");
	usleep(20000);
	TEST_ASSERT_EQ(__atomic_load_n(&mapping.header->completion_tail,
				       __ATOMIC_ACQUIRE), 3);
	TEST_ASSERT_EQ(cancel_dispatch(run_arg.executor_fd, domain_generation,
				       executor_generation, 4),
		       KVM_EXEC_CANCEL_ACCEPTED);
	kick_dispatch(run_arg.executor_fd, domain_generation,
		      executor_generation, 4);
	completion = consume_dispatch_completion(&mapping);
	TEST_ASSERT_EQ(completion.status,
		       KVM_EXEC_COMPLETE_CANCELLED_BEFORE_APPLY);
	TEST_ASSERT_EQ(completion.owned_capsule_id, 0);
	TEST_ASSERT_EQ(cancel_dispatch(run_arg.executor_fd, domain_generation,
				       executor_generation, 4),
		       KVM_EXEC_CANCEL_ALREADY_CANCELLED);

	command.request_sequence = 5;
	TEST_ASSERT(publish_dispatch_command(&mapping, command),
		    "second switch command was unexpectedly full");
	kick_dispatch(run_arg.executor_fd, domain_generation,
		      executor_generation, 5);
	completion = consume_dispatch_completion(&mapping);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_APPLIED);
	TEST_ASSERT_EQ(cancel_dispatch(run_arg.executor_fd, domain_generation,
				       executor_generation, 5),
		       KVM_EXEC_CANCEL_APPLIED);

	stale_cancel.domain_generation = domain_generation + 1;
	stale_cancel.executor_generation = executor_generation;
	assert_ioctl_errno(run_arg.executor_fd, KVM_EXEC_CANCEL, &stale_cancel,
			   ESTALE);
	stale_cancel.domain_generation = domain_generation;
	stale_cancel.executor_generation = executor_generation + 1;
	assert_ioctl_errno(run_arg.executor_fd, KVM_EXEC_CANCEL, &stale_cancel,
			   ESTALE);

	/* Apply and cancellation race at one serialized ownership point. */
	for (command.request_sequence = 6; command.request_sequence < 134;
	     command.request_sequence++) {
		uint32_t cancel_status;

		command.expected_current_id = 41;
		command.expected_current_generation = 7;
		TEST_ASSERT(publish_dispatch_command(&mapping, command),
			    "race command was unexpectedly full");
		kick_dispatch(run_arg.executor_fd, domain_generation,
			      executor_generation, command.request_sequence);
		cancel_status = cancel_dispatch(run_arg.executor_fd,
						domain_generation,
						executor_generation,
						command.request_sequence);
		completion = consume_dispatch_completion(&mapping);
		TEST_ASSERT_EQ(completion.request_sequence,
			       command.request_sequence);
		if (cancel_status == KVM_EXEC_CANCEL_ACCEPTED) {
			TEST_ASSERT_EQ(completion.status,
				       KVM_EXEC_COMPLETE_CANCELLED_BEFORE_APPLY);
		} else {
			TEST_ASSERT_EQ(cancel_status, KVM_EXEC_CANCEL_APPLIED);
			TEST_ASSERT_EQ(completion.status,
				       KVM_EXEC_COMPLETE_APPLIED);
		}
		TEST_ASSERT_EQ(completion.owned_capsule_id, 41);
		TEST_ASSERT_EQ(mapping.header->completion_head,
			       mapping.header->completion_tail);
	}

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	pthread_join(thread, NULL);
	TEST_ASSERT(!run_arg.ret,
		    "KVM_EXEC_RUN_DISPATCH returned %d errno %d",
		    run_arg.ret, run_arg.error);
	TEST_ASSERT_EQ(run_arg.run.return_reason,
		       KVM_EXEC_RETURN_DOMAIN_PAUSED);
	TEST_ASSERT_EQ(run_arg.run.run_result, -EINTR);
	TEST_ASSERT_EQ(run_arg.run.owned_capsule_id, 41);
	TEST_ASSERT_EQ(mapping.header->kernel_kick_count, 133);

	munmap(mapping.header, KVM_EXEC_DISPATCH_MMAP_SIZE);
	close(run_arg.executor_fd);
	detach_vcpu(domain_fd, 41, 7);
	close(domain_fd);
	kvm_vm_free(vm);
}

static void test_dynamic_ring_backpressure_and_corruption(int kvm_fd)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_DYNAMIC_DISPATCH;
	struct kvm_exec_command command = {
		.opcode = KVM_EXEC_CMD_SWITCH,
		.target_capsule_id = 999,
		.target_lifecycle_generation = 1,
	};
	struct kvm_exec_run_dispatch run = {
		.size = sizeof(run),
		.flags = KVM_EXEC_DISPATCH_F_RETURN_IF_EMPTY,
	};
	struct kvm_exec_completion completion;
	struct dispatch_mapping mapping;
	uint64_t domain_generation, executor_generation;
	int domain_fd, executor_fd, ret, i;

	domain_fd = create_domain_with_features(kvm_fd, 1, 1, features,
						&domain_generation);
	executor_fd = create_executor(domain_fd, 0x702, &executor_generation);
	mapping = map_dispatch(executor_fd);
	command.domain_generation = domain_generation;
	command.executor_generation = executor_generation;
	run.domain_generation = domain_generation;
	run.executor_generation = executor_generation;

	for (i = 0; i < KVM_EXEC_DISPATCH_RING_ENTRIES; i++) {
		command.request_sequence = i + 1;
		command.reserved[0] = i == 0;
		TEST_ASSERT(publish_dispatch_command(&mapping, command),
			    "command ring filled before its advertised capacity");
	}
	command.request_sequence++;
	command.reserved[0] = 0;
	TEST_ASSERT(!publish_dispatch_command(&mapping, command),
		    "command producer overwrote a full ring");

	ret = ioctl(executor_fd, KVM_EXEC_RUN_DISPATCH, &run);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN_DISPATCH, ret));
	TEST_ASSERT_EQ(run.return_reason, KVM_EXEC_RETURN_DISPATCH_EMPTY);
	TEST_ASSERT_EQ(run.command_head, KVM_EXEC_DISPATCH_RING_ENTRIES);
	TEST_ASSERT_EQ(run.completion_tail, KVM_EXEC_DISPATCH_RING_ENTRIES);

	TEST_ASSERT(publish_dispatch_command(&mapping, command),
		    "command ring did not reopen after kernel consumption");
	ret = ioctl(executor_fd, KVM_EXEC_RUN_DISPATCH, &run);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN_DISPATCH, ret));
	TEST_ASSERT_EQ(run.return_reason, KVM_EXEC_RETURN_COMPLETION_FULL);
	TEST_ASSERT_EQ(run.run_result, -ENOSPC);
	TEST_ASSERT_EQ(run.command_head, KVM_EXEC_DISPATCH_RING_ENTRIES);

	for (i = 0; i < KVM_EXEC_DISPATCH_RING_ENTRIES; i++) {
		completion = consume_dispatch_completion(&mapping);
		TEST_ASSERT_EQ(completion.request_sequence, i + 1);
		TEST_ASSERT_EQ(completion.status,
			       i ? KVM_EXEC_COMPLETE_TARGET_UNKNOWN :
				   KVM_EXEC_COMPLETE_REJECTED);
	}
	ret = ioctl(executor_fd, KVM_EXEC_RUN_DISPATCH, &run);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN_DISPATCH, ret));
	TEST_ASSERT_EQ(run.return_reason, KVM_EXEC_RETURN_DISPATCH_EMPTY);
	completion = consume_dispatch_completion(&mapping);
	TEST_ASSERT_EQ(completion.request_sequence,
		       KVM_EXEC_DISPATCH_RING_ENTRIES + 1);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_TARGET_UNKNOWN);

	/* Duplicate sequences terminate once and do not poison the next entry. */
	command.request_sequence = KVM_EXEC_DISPATCH_RING_ENTRIES + 2;
	TEST_ASSERT(publish_dispatch_command(&mapping, command),
		    "first duplicate-sequence command did not publish");
	TEST_ASSERT(publish_dispatch_command(&mapping, command),
		    "second duplicate-sequence command did not publish");
	command.request_sequence++;
	TEST_ASSERT(publish_dispatch_command(&mapping, command),
		    "post-duplicate command did not publish");
	ret = ioctl(executor_fd, KVM_EXEC_RUN_DISPATCH, &run);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN_DISPATCH, ret));
	completion = consume_dispatch_completion(&mapping);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_TARGET_UNKNOWN);
	completion = consume_dispatch_completion(&mapping);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_REJECTED);
	completion = consume_dispatch_completion(&mapping);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_TARGET_UNKNOWN);

	/* A producer distance beyond capacity is a controlled fatal ring error. */
	__atomic_store_n(&mapping.header->command_tail,
			 mapping.header->command_head +
			 KVM_EXEC_DISPATCH_RING_ENTRIES + 1,
			 __ATOMIC_RELEASE);
	ret = ioctl(executor_fd, KVM_EXEC_RUN_DISPATCH, &run);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_EXEC_RUN_DISPATCH, ret));
	TEST_ASSERT_EQ(run.return_reason, KVM_EXEC_RETURN_DISPATCH_CORRUPT);
	TEST_ASSERT_EQ(run.run_result, -EPROTO);
	TEST_ASSERT_EQ(run.corruption_count, 1);
	TEST_ASSERT_EQ(mapping.header->kernel_corruption_count, 1);

	munmap(mapping.header, KVM_EXEC_DISPATCH_MMAP_SIZE);
	close(executor_fd);
	close(domain_fd);
}

static void test_dynamic_cross_vm_seeded_trace(int kvm_fd)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN |
				  KVM_EXEC_FEATURE_CROSS_VM_CHAIN |
				  KVM_EXEC_FEATURE_DYNAMIC_DISPATCH;
	const uint64_t capsule_ids[2] = { 501, 902 };
	const uint64_t generations[2] = { 51, 92 };
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	struct kvm_exec_command command = {
		.opcode = KVM_EXEC_CMD_SWITCH,
	};
	struct dispatch_run_arg run_arg = { };
	struct dispatch_mapping mapping;
	struct kvm_exec_completion completion;
	struct kvm_vcpu *vcpus[2];
	struct kvm_vm *vms[2];
	uint64_t *counts[2], *errors[2];
	uint64_t domain_generation, executor_generation;
	uint64_t previous_id = 0, previous_generation = 0;
	uint64_t random = 0x7018c055600dULL;
	pthread_t thread;
	int domain_fd, i;

	vms[0] = vm_create_with_one_vcpu(&vcpus[0], guest_single_step_trace);
	vms[1] = vm_create_with_one_vcpu(&vcpus[1], guest_single_step_trace);
	for (i = 0; i < 2; i++) {
		vcpu_args_set(vcpus[i], 1, i);
		disable_nested_cpuid(vcpus[i]);
		vcpu_guest_debug_set(vcpus[i], &debug);
		counts[i] = addr_gva2hva(vms[i], (vm_vaddr_t)trace_counts);
		errors[i] = addr_gva2hva(vms[i],
					 (vm_vaddr_t)trace_state_errors);
		memset(counts[i], 0, sizeof(trace_counts));
		memset(errors[i], 0, sizeof(trace_state_errors));
	}

	domain_fd = create_domain_with_features(kvm_fd, 2, 1, features,
						&domain_generation);
	for (i = 0; i < 2; i++)
		attach_vcpu(domain_fd, vcpus[i]->fd, capsule_ids[i],
			    generations[i]);
	run_arg.executor_fd = create_executor(domain_fd, 0x703,
					      &executor_generation);
	mapping = map_dispatch(run_arg.executor_fd);
	run_arg.run.size = sizeof(run_arg.run);
	run_arg.run.domain_generation = domain_generation;
	run_arg.run.executor_generation = executor_generation;
	command.domain_generation = domain_generation;
	command.executor_generation = executor_generation;

	for (i = 0; i < 4096; i++) {
		uint64_t progress_before;
		int target;

		random ^= random << 13;
		random ^= random >> 7;
		random ^= random << 17;
		target = random & 1;
		progress_before = READ_ONCE(counts[target][target]);
		command.request_sequence = i + 1;
		command.expected_current_id = previous_id;
		command.expected_current_generation = previous_generation;
		command.target_capsule_id = capsule_ids[target];
		command.target_lifecycle_generation = generations[target];
		command.user_cookie = random;
		TEST_ASSERT(publish_dispatch_command(&mapping, command),
			    "seeded command ring unexpectedly full at step %d", i);
		if (!i) {
			TEST_ASSERT(!pthread_create(&thread, NULL, dispatch_runner,
						    &run_arg),
				    "pthread_create failed");
		} else {
			kick_dispatch(run_arg.executor_fd, domain_generation,
				      executor_generation, i + 1);
		}
		completion = consume_dispatch_completion(&mapping);
		TEST_ASSERT_EQ(completion.request_sequence, i + 1);
		TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_APPLIED);
		TEST_ASSERT_EQ(completion.previous_capsule_id, previous_id);
		TEST_ASSERT_EQ(completion.owned_capsule_id,
			       capsule_ids[target]);
		TEST_ASSERT_EQ(completion.owned_lifecycle_generation,
			       generations[target]);
		TEST_ASSERT_EQ(completion.user_cookie, random);
		wait_for_trace_progress(&counts[target][target], progress_before);
		previous_id = capsule_ids[target];
		previous_generation = generations[target];
	}

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	pthread_join(thread, NULL);
	TEST_ASSERT(!run_arg.ret,
		    "dynamic seeded runner returned %d errno %d",
		    run_arg.ret, run_arg.error);
	TEST_ASSERT_EQ(run_arg.run.return_reason,
		       KVM_EXEC_RETURN_DOMAIN_PAUSED);
	TEST_ASSERT_EQ(run_arg.run.owned_capsule_id, previous_id);
	TEST_ASSERT(READ_ONCE(counts[0][0]) > 0,
		    "first dynamic capsule made no guest progress");
	TEST_ASSERT(READ_ONCE(counts[1][1]) > 0,
		    "second dynamic capsule made no guest progress");
	TEST_ASSERT_EQ(READ_ONCE(errors[0][0]), 0);
	TEST_ASSERT_EQ(READ_ONCE(errors[1][1]), 0);

	munmap(mapping.header, KVM_EXEC_DISPATCH_MMAP_SIZE);
	close(run_arg.executor_fd);
	for (i = 0; i < 2; i++)
		detach_vcpu(domain_fd, capsule_ids[i], generations[i]);
	close(domain_fd);
	kvm_vm_free(vms[1]);
	kvm_vm_free(vms[0]);
}

static void test_dynamic_two_executor_migration(int kvm_fd)
{
	const uint64_t features = KVM_EXEC_FEATURE_BASE_OBJECTS |
				  KVM_EXEC_FEATURE_INTRA_VM_CHAIN |
				  KVM_EXEC_FEATURE_CROSS_VM_CHAIN |
				  KVM_EXEC_FEATURE_DYNAMIC_DISPATCH;
	const uint64_t capsule_ids[2] = { 711, 822 };
	const uint64_t generations[2] = { 17, 28 };
	struct kvm_guest_debug debug = {
		.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
	};
	struct kvm_exec_command command = {
		.opcode = KVM_EXEC_CMD_SWITCH,
	};
	struct dispatch_run_arg runners[2] = { };
	struct dispatch_mapping mappings[2];
	struct kvm_exec_completion completion;
	struct kvm_vcpu *vcpus[2];
	struct kvm_vm *vms[2];
	uint64_t domain_generation, executor_generations[2];
	pthread_t threads[2];
	int domain_fd, i;

	for (i = 0; i < 2; i++) {
		vms[i] = vm_create_with_one_vcpu(&vcpus[i],
						 guest_single_step_trace);
		vcpu_args_set(vcpus[i], 1, i);
		disable_nested_cpuid(vcpus[i]);
		vcpu_guest_debug_set(vcpus[i], &debug);
	}
	domain_fd = create_domain_with_features(kvm_fd, 2, 2, features,
						&domain_generation);
	for (i = 0; i < 2; i++) {
		attach_vcpu(domain_fd, vcpus[i]->fd, capsule_ids[i],
			    generations[i]);
		runners[i].executor_fd =
			create_executor(domain_fd, 0x710 + i,
					&executor_generations[i]);
		mappings[i] = map_dispatch(runners[i].executor_fd);
		runners[i].run.size = sizeof(runners[i].run);
		runners[i].run.domain_generation = domain_generation;
		runners[i].run.executor_generation = executor_generations[i];
		command.request_sequence = 1;
		command.domain_generation = domain_generation;
		command.executor_generation = executor_generations[i];
		command.expected_current_id = 0;
		command.expected_current_generation = 0;
		command.target_capsule_id = capsule_ids[i];
		command.target_lifecycle_generation = generations[i];
		TEST_ASSERT(publish_dispatch_command(&mappings[i], command),
			    "initial migration command did not publish");
		TEST_ASSERT(!pthread_create(&threads[i], NULL, dispatch_runner,
					    &runners[i]),
			    "pthread_create failed");
		completion = consume_dispatch_completion(&mappings[i]);
		TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_APPLIED);
		TEST_ASSERT_EQ(completion.owned_capsule_id, capsule_ids[i]);
	}

	command = (struct kvm_exec_command) {
		.opcode = KVM_EXEC_CMD_SWITCH,
		.request_sequence = 2,
		.domain_generation = domain_generation,
		.executor_generation = executor_generations[1],
		.expected_current_id = capsule_ids[1],
		.expected_current_generation = generations[1],
		.target_capsule_id = capsule_ids[0],
		.target_lifecycle_generation = generations[0],
	};
	TEST_ASSERT(publish_dispatch_command(&mappings[1], command),
		    "busy-target command did not publish");
	kick_dispatch(runners[1].executor_fd, domain_generation,
		      executor_generations[1], 2);
	completion = consume_dispatch_completion(&mappings[1]);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_TARGET_BUSY);
	TEST_ASSERT_EQ(completion.owned_capsule_id, capsule_ids[1]);

	command = (struct kvm_exec_command) {
		.opcode = KVM_EXEC_CMD_RELEASE,
		.request_sequence = 2,
		.domain_generation = domain_generation,
		.executor_generation = executor_generations[0],
		.expected_current_id = capsule_ids[0],
		.expected_current_generation = generations[0],
	};
	TEST_ASSERT(publish_dispatch_command(&mappings[0], command),
		    "source release command did not publish");
	kick_dispatch(runners[0].executor_fd, domain_generation,
		      executor_generations[0], 2);
	completion = consume_dispatch_completion(&mappings[0]);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_RETURNED);
	TEST_ASSERT_EQ(completion.owned_capsule_id, 0);

	command = (struct kvm_exec_command) {
		.opcode = KVM_EXEC_CMD_SWITCH,
		.request_sequence = 3,
		.domain_generation = domain_generation,
		.executor_generation = executor_generations[1],
		.expected_current_id = capsule_ids[1],
		.expected_current_generation = generations[1],
		.target_capsule_id = capsule_ids[0],
		.target_lifecycle_generation = generations[0],
	};
	TEST_ASSERT(publish_dispatch_command(&mappings[1], command),
		    "destination claim command did not publish");
	kick_dispatch(runners[1].executor_fd, domain_generation,
		      executor_generations[1], 3);
	completion = consume_dispatch_completion(&mappings[1]);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_APPLIED);
	TEST_ASSERT_EQ(completion.owned_capsule_id, capsule_ids[0]);

	command = (struct kvm_exec_command) {
		.opcode = KVM_EXEC_CMD_SWITCH,
		.request_sequence = 3,
		.domain_generation = domain_generation,
		.executor_generation = executor_generations[0],
		.target_capsule_id = capsule_ids[1],
		.target_lifecycle_generation = generations[1],
	};
	TEST_ASSERT(publish_dispatch_command(&mappings[0], command),
		    "released target command did not publish");
	kick_dispatch(runners[0].executor_fd, domain_generation,
		      executor_generations[0], 3);
	completion = consume_dispatch_completion(&mappings[0]);
	TEST_ASSERT_EQ(completion.status, KVM_EXEC_COMPLETE_APPLIED);
	TEST_ASSERT_EQ(completion.owned_capsule_id, capsule_ids[1]);

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
	for (i = 0; i < 2; i++) {
		pthread_join(threads[i], NULL);
		TEST_ASSERT(!runners[i].ret,
			    "migration runner %d returned %d errno %d", i,
			    runners[i].ret, runners[i].error);
		TEST_ASSERT_EQ(runners[i].run.return_reason,
			       KVM_EXEC_RETURN_DOMAIN_PAUSED);
		munmap(mappings[i].header, KVM_EXEC_DISPATCH_MMAP_SIZE);
		close(runners[i].executor_fd);
		detach_vcpu(domain_fd, capsule_ids[i], generations[i]);
	}
	close(domain_fd);
	kvm_vm_free(vms[1]);
	kvm_vm_free(vms[0]);
}

static void run_executor_boundary_test(int kvm_fd, bool pause)
{
	struct executor_run_arg run_arg = { };
	uint64_t *started;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	pthread_t thread;
	uint64_t domain_generation, executor_generation;
	int domain_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_spin);
	disable_nested_cpuid(vcpu);
	started = guest_started_hva(vm);
	domain_fd = create_domain(kvm_fd, 1, 1, &domain_generation);
	attach_vcpu(domain_fd, vcpu->fd, 1, 1);
	run_arg.executor_fd =
		create_executor(domain_fd, 1, &executor_generation);
	run_arg.run.size = sizeof(run_arg.run);
	run_arg.run.request_sequence = 1;
	run_arg.run.domain_generation = domain_generation;
	run_arg.run.executor_generation = executor_generation;
	run_arg.run.target_capsule_id = 1;
	run_arg.run.target_lifecycle_generation = 1;
	TEST_ASSERT(!pthread_create(&thread, NULL, executor_runner, &run_arg),
		    "pthread_create failed");
	wait_for_guest(started);

	if (pause) {
		control_domain(domain_fd, KVM_EXEC_PAUSE);
		control_domain(domain_fd, KVM_EXEC_DRAIN);
	} else {
		TEST_ASSERT(!pthread_kill(thread, SIGUSR1),
			    "pthread_kill failed");
	}
	pthread_join(thread, NULL);
	TEST_ASSERT(!run_arg.ret,
		    "KVM_EXEC_RUN returned %d errno %d", run_arg.ret,
		    run_arg.error);
	TEST_ASSERT_EQ(run_arg.run.run_result, -EINTR);
	TEST_ASSERT_EQ(run_arg.run.return_reason,
		       pause ? KVM_EXEC_RETURN_DOMAIN_PAUSED :
			       KVM_EXEC_RETURN_SIGNAL);

	close(run_arg.executor_fd);
	detach_vcpu(domain_fd, 1, 1);
	close(domain_fd);
	kvm_vm_free(vm);
}

static void test_pause_drain_and_runner_signal(int kvm_fd)
{
	struct sigaction action = {
		.sa_handler = signal_handler,
	};

	sigemptyset(&action.sa_mask);
	TEST_ASSERT(!sigaction(SIGUSR1, &action, NULL),
		    "sigaction failed, errno %d", errno);
	test_attach_rejects_active_kvm_run(kvm_fd);
	run_executor_boundary_test(kvm_fd, true);
	run_executor_boundary_test(kvm_fd, false);
}

static void create_raw_vm_vcpu(int kvm_fd, int *vm_fd, int *vcpu_fd)
{
	*vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
	TEST_ASSERT(*vm_fd >= 0, KVM_IOCTL_ERROR(KVM_CREATE_VM, *vm_fd));
	*vcpu_fd = ioctl(*vm_fd, KVM_CREATE_VCPU, 0);
	TEST_ASSERT(*vcpu_fd >= 0,
		    KVM_IOCTL_ERROR(KVM_CREATE_VCPU, *vcpu_fd));
}

static void test_attached_capsule_accepts_interrupt_before_entry(int kvm_fd)
{
	struct kvm_interrupt irq = { .irq = 32 };
	struct kvm_regs regs;
	uint64_t generation;
	int domain_fd, vm_fd, vcpu_fd, ret;

	create_raw_vm_vcpu(kvm_fd, &vm_fd, &vcpu_fd);
	domain_fd = create_domain(kvm_fd, 1, 1, &generation);
	attach_vcpu(domain_fd, vcpu_fd, 1, 1);

	ret = ioctl(vcpu_fd, KVM_INTERRUPT, &irq);
	TEST_ASSERT(!ret, KVM_IOCTL_ERROR(KVM_INTERRUPT, ret));
	assert_ioctl_errno(vcpu_fd, KVM_GET_REGS, &regs, EBUSY);

	detach_vcpu(domain_fd, 1, 1);
	close(domain_fd);
	close(vcpu_fd);
	close(vm_fd);
}

static void test_fd_close_orders(int kvm_fd)
{
	static const int orders[24][4] = {
		{ 0, 1, 2, 3 }, { 0, 1, 3, 2 }, { 0, 2, 1, 3 },
		{ 0, 2, 3, 1 }, { 0, 3, 1, 2 }, { 0, 3, 2, 1 },
		{ 1, 0, 2, 3 }, { 1, 0, 3, 2 }, { 1, 2, 0, 3 },
		{ 1, 2, 3, 0 }, { 1, 3, 0, 2 }, { 1, 3, 2, 0 },
		{ 2, 0, 1, 3 }, { 2, 0, 3, 1 }, { 2, 1, 0, 3 },
		{ 2, 1, 3, 0 }, { 2, 3, 0, 1 }, { 2, 3, 1, 0 },
		{ 3, 0, 1, 2 }, { 3, 0, 2, 1 }, { 3, 1, 0, 2 },
		{ 3, 1, 2, 0 }, { 3, 2, 0, 1 }, { 3, 2, 1, 0 },
	};
	uint64_t domain_generation, executor_generation;
	int fds[4], order, i;

	for (order = 0; order < 24; order++) {
		create_raw_vm_vcpu(kvm_fd, &fds[3], &fds[2]);
		fds[0] = create_domain(kvm_fd, 1, 1, &domain_generation);
		attach_vcpu(fds[0], fds[2], 1, 1);
		fds[1] = create_executor(fds[0], order,
					 &executor_generation);
		for (i = 0; i < 4; i++)
			TEST_ASSERT(!close(fds[orders[order][i]]),
				    "close-order %d failed at step %d", order, i);
	}
}

static void test_wrong_mm(int kvm_fd, const char *self_path)
{
	struct kvm_exec_domain_control control = { .size = sizeof(control) };
	uint64_t generation;
	char fd_string[32];
	pid_t child;
	int domain_fd, status;

	domain_fd = create_domain(kvm_fd, 1, 1, &generation);
	child = fork();
	TEST_ASSERT(child >= 0, "fork failed, errno %d", errno);
	if (!child) {
		errno = 0;
		if (ioctl(domain_fd, KVM_EXEC_PAUSE, &control) == -1 &&
		    errno == EIO)
			_exit(0);
		_exit(1);
	}
	waitpid(child, &status, 0);
	TEST_ASSERT(WIFEXITED(status) && !WEXITSTATUS(status),
		    "forked wrong-mm check failed");

	TEST_ASSERT(!fcntl(domain_fd, F_SETFD, 0),
		    "failed to clear close-on-exec");
	snprintf(fd_string, sizeof(fd_string), "%d", domain_fd);
	child = fork();
	TEST_ASSERT(child >= 0, "fork failed, errno %d", errno);
	if (!child) {
		execl(self_path, self_path, "--wrong-mm-fd", fd_string, NULL);
		_exit(2);
	}
	waitpid(child, &status, 0);
	TEST_ASSERT(WIFEXITED(status) && !WEXITSTATUS(status),
		    "exec wrong-mm check failed");
	close(domain_fd);
}

static void test_malformed_and_stale_requests(int kvm_fd)
{
	struct kvm_exec_domain_create bad_create = {
		.size = sizeof(bad_create),
		.max_capsules = 1,
		.max_executors = 1,
		.requested_features = KVM_EXEC_FEATURE_BASE_OBJECTS,
	};
	struct kvm_exec_attach_vcpu attach = {
		.size = sizeof(attach),
		.capsule_id = 1,
		.lifecycle_generation = 1,
	};
	struct kvm_exec_detach_vcpu detach = {
		.size = sizeof(detach),
		.capsule_id = 1,
		.lifecycle_generation = 1,
	};
	struct kvm_exec_create_executor bad_executor = {
		.size = sizeof(bad_executor),
		.flags = KVM_EXECUTOR_F_STRICT_CPU,
		.requested_cpu = KVM_EXEC_CPU_ANY,
	};
	struct kvm_exec_domain_control bad_control = {
		.size = sizeof(bad_control) - 1,
	};
	struct kvm_exec_run run = { .size = sizeof(run) };
	uint64_t domain_generation, other_generation, executor_generation;
	int domain_fd, other_domain_fd, executor_fd, vm_fd, vcpu_fd;

	bad_create.flags = 1;
	assert_ioctl_errno(kvm_fd, KVM_CREATE_EXEC_DOMAIN, &bad_create, EINVAL);
	bad_create.flags = 0;
	bad_create.reserved[0] = 1;
	assert_ioctl_errno(kvm_fd, KVM_CREATE_EXEC_DOMAIN, &bad_create, EINVAL);
	bad_create.reserved[0] = 0;
	bad_create.requested_features |= 1ULL << 63;
	assert_ioctl_errno(kvm_fd, KVM_CREATE_EXEC_DOMAIN, &bad_create, EINVAL);

	create_raw_vm_vcpu(kvm_fd, &vm_fd, &vcpu_fd);
	domain_fd = create_domain(kvm_fd, 1, 1, &domain_generation);
	other_domain_fd = create_domain(kvm_fd, 1, 1, &other_generation);
	attach.vcpu_fd = kvm_fd;
	assert_ioctl_errno(domain_fd, KVM_EXEC_ATTACH_VCPU, &attach, EINVAL);
	attach.vcpu_fd = vcpu_fd;
	attach.flags = 1;
	assert_ioctl_errno(domain_fd, KVM_EXEC_ATTACH_VCPU, &attach, EINVAL);
	attach.flags = 0;
	attach_vcpu(domain_fd, vcpu_fd, 1, 1);
	assert_ioctl_errno(domain_fd, KVM_EXEC_ATTACH_VCPU, &attach, EEXIST);
	assert_ioctl_errno(other_domain_fd, KVM_EXEC_ATTACH_VCPU, &attach, EBUSY);
	detach_vcpu(domain_fd, 1, 1);
	assert_ioctl_errno(domain_fd, KVM_EXEC_ATTACH_VCPU, &attach, ESTALE);
	attach.lifecycle_generation = 2;
	attach_vcpu(domain_fd, vcpu_fd, 1, 2);

	assert_ioctl_errno(domain_fd, KVM_EXEC_CREATE_EXECUTOR, &bad_executor,
			   EINVAL);
	executor_fd = create_executor(domain_fd, 1, &executor_generation);
	run.request_sequence = 1;
	run.domain_generation = domain_generation + 1;
	run.executor_generation = executor_generation;
	run.target_capsule_id = 1;
	run.target_lifecycle_generation = 2;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN, &run, ESTALE);
	run.domain_generation = domain_generation;
	run.target_lifecycle_generation = 1;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN, &run, ESTALE);
	run.target_lifecycle_generation = 2;
	run.target_capsule_id = 2;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN, &run, ENOENT);
	assert_ioctl_errno(domain_fd, KVM_EXEC_PAUSE, &bad_control, EINVAL);
	control_domain(domain_fd, KVM_EXEC_PAUSE);
	run.target_capsule_id = 1;
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN, &run, EBUSY);
	control_domain(domain_fd, KVM_EXEC_DRAIN);

	close(domain_fd);
	assert_ioctl_errno(executor_fd, KVM_EXEC_RUN, &run, ESHUTDOWN);
	close(executor_fd);
	close(other_domain_fd);
	close(vcpu_fd);
	close(vm_fd);
}

static void test_deterministic_malformed_fuzz(int kvm_fd)
{
	struct kvm_exec_domain_create create;
	struct kvm_exec_attach_vcpu attach;
	struct kvm_exec_detach_vcpu detach;
	struct kvm_exec_create_executor create_executor_req;
	struct kvm_exec_domain_control control;
	struct kvm_exec_run run;
	uint64_t domain_generation, executor_generation, value;
	int domain_fd, executor_fd, vm_fd, vcpu_fd;
	size_t reserved_index;
	int i;

	for (i = 0; i < 96; i++) {
		create = (struct kvm_exec_domain_create) {
			.size = sizeof(create),
			.max_capsules = 1,
			.max_executors = 1,
			.requested_features = KVM_EXEC_FEATURE_BASE_OBJECTS,
		};
		value = (fuzz_next() >> 1) | 1;
		switch (i % 6) {
		case 0:
			create.size = sizeof(create) + (value & 15) + 1;
			break;
		case 1:
			create.flags = value;
			break;
		case 2:
			create.max_capsules = 0;
			break;
		case 3:
			create.max_executors = 0;
			break;
		case 4:
			create.requested_features |= 1ULL << 63;
			break;
		case 5:
			create.reserved[value % ARRAY_SIZE(create.reserved)] = value;
			break;
		}
		assert_ioctl_errno(kvm_fd, KVM_CREATE_EXEC_DOMAIN, &create, EINVAL);
	}

	create_raw_vm_vcpu(kvm_fd, &vm_fd, &vcpu_fd);
	domain_fd = create_domain(kvm_fd, 1, 1, &domain_generation);
	for (i = 0; i < 96; i++) {
		attach = (struct kvm_exec_attach_vcpu) {
			.size = sizeof(attach),
			.vcpu_fd = vcpu_fd,
			.capsule_id = 1,
			.lifecycle_generation = 1,
		};
		value = (fuzz_next() >> 1) | 1;
		switch (i % 6) {
		case 0:
			attach.size = sizeof(attach) + (value & 15) + 1;
			break;
		case 1:
			attach.flags = value;
			break;
		case 2:
			attach.reserved0 = value;
			break;
		case 3:
			attach.capsule_id = 0;
			break;
		case 4:
			attach.lifecycle_generation = 0;
			break;
		case 5:
			attach.reserved[value % ARRAY_SIZE(attach.reserved)] = value;
			break;
		}
		assert_ioctl_errno(domain_fd, KVM_EXEC_ATTACH_VCPU, &attach,
				   EINVAL);
	}
	attach_vcpu(domain_fd, vcpu_fd, 1, 1);

	for (i = 0; i < 96; i++) {
		create_executor_req = (struct kvm_exec_create_executor) {
			.size = sizeof(create_executor_req),
			.requested_cpu = KVM_EXEC_CPU_ANY,
		};
		value = (fuzz_next() >> 1) | 1;
		switch (i % 6) {
		case 0:
			create_executor_req.size =
				sizeof(create_executor_req) + (value & 15) + 1;
			break;
		case 1:
			create_executor_req.flags = 2U << (value % 30);
			break;
		case 2:
			create_executor_req.flags = KVM_EXECUTOR_F_STRICT_CPU;
			break;
		case 3:
			create_executor_req.requested_cpu = UINT32_MAX - 1;
			break;
		case 4:
			create_executor_req.reserved0 = value;
			break;
		case 5:
			reserved_index =
				value % ARRAY_SIZE(create_executor_req.reserved);
			create_executor_req.reserved[reserved_index] = value;
			break;
		}
		assert_ioctl_errno(domain_fd, KVM_EXEC_CREATE_EXECUTOR,
				   &create_executor_req, EINVAL);
	}
	executor_fd = create_executor(domain_fd, 1, &executor_generation);

	for (i = 0; i < 128; i++) {
		run = (struct kvm_exec_run) {
			.size = sizeof(run),
			.request_sequence = 1,
			.domain_generation = domain_generation,
			.executor_generation = executor_generation,
			.target_capsule_id = 1,
			.target_lifecycle_generation = 1,
		};
		value = (fuzz_next() >> 1) | 1;
		switch (i % 10) {
		case 0:
			run.size = sizeof(run) + (value & 15) + 1;
			break;
		case 1:
			run.flags = value;
			break;
		case 2:
			run.request_sequence = 0;
			break;
		case 3:
			run.target_capsule_id = 0;
			break;
		case 4:
			run.target_lifecycle_generation = 0;
			break;
		case 5:
			run.reserved[value % ARRAY_SIZE(run.reserved)] = value;
			break;
		case 6:
			run.domain_generation += value;
			break;
		case 7:
			run.executor_generation += value;
			break;
		case 8:
			run.target_lifecycle_generation += value;
			break;
		case 9:
			run.target_capsule_id += value;
			break;
		}
		assert_ioctl_errno(executor_fd, KVM_EXEC_RUN, &run,
				   i % 10 < 6 ? EINVAL :
				   i % 10 < 9 ? ESTALE : ENOENT);
	}

	for (i = 0; i < 64; i++) {
		control = (struct kvm_exec_domain_control) {
			.size = sizeof(control),
		};
		value = (fuzz_next() >> 1) | 1;
		switch (i % 3) {
		case 0:
			control.size = sizeof(control) + (value & 15) + 1;
			break;
		case 1:
			control.flags = value;
			break;
		case 2:
			control.reserved[value % ARRAY_SIZE(control.reserved)] = value;
			break;
		}
		assert_ioctl_errno(domain_fd, KVM_EXEC_PAUSE, &control, EINVAL);
	}

	for (i = 0; i < 64; i++) {
		detach = (struct kvm_exec_detach_vcpu) {
			.size = sizeof(detach),
			.capsule_id = 1,
			.lifecycle_generation = 1,
		};
		value = (fuzz_next() >> 1) | 1;
		switch (i % 5) {
		case 0:
			detach.size = sizeof(detach) + (value & 15) + 1;
			break;
		case 1:
			detach.flags = value;
			break;
		case 2:
			detach.capsule_id = 0;
			break;
		case 3:
			detach.lifecycle_generation = 0;
			break;
		case 4:
			detach.reserved[value % ARRAY_SIZE(detach.reserved)] = value;
			break;
		}
		assert_ioctl_errno(domain_fd, KVM_EXEC_DETACH_VCPU, &detach,
				   EINVAL);
	}

	close(executor_fd);
	detach_vcpu(domain_fd, 1, 1);
	close(domain_fd);
	close(vcpu_fd);
	close(vm_fd);
}

static int wrong_mm_exec_check(const char *fd_string)
{
	struct kvm_exec_domain_control control = { .size = sizeof(control) };
	int fd = atoi(fd_string);

	errno = 0;
	return ioctl(fd, KVM_EXEC_PAUSE, &control) == -1 && errno == EIO ? 0 : 1;
}

int main(int argc, char **argv)
{
	int kvm_fd, capability;

	if (argc == 3 && !strcmp(argv[1], "--wrong-mm-fd"))
		return wrong_mm_exec_check(argv[2]);

	kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);

	TEST_ASSERT(kvm_fd >= 0, "open /dev/kvm failed, errno: %d", errno);
	capability = ioctl(kvm_fd, KVM_CHECK_EXTENSION,
			   KVM_CAP_VCPU_EXEC_DOMAIN);
	TEST_REQUIRE((capability & (KVM_EXEC_FEATURE_BASE_OBJECTS |
				    KVM_EXEC_FEATURE_INTRA_VM_CHAIN |
				    KVM_EXEC_FEATURE_CROSS_VM_CHAIN |
				    KVM_EXEC_FEATURE_DYNAMIC_DISPATCH |
				    KVM_EXEC_FEATURE_SYNC_EXITS)) ==
		     (KVM_EXEC_FEATURE_BASE_OBJECTS |
		      KVM_EXEC_FEATURE_INTRA_VM_CHAIN |
		      KVM_EXEC_FEATURE_CROSS_VM_CHAIN |
		      KVM_EXEC_FEATURE_DYNAMIC_DISPATCH |
		      KVM_EXEC_FEATURE_SYNC_EXITS));
	if (argc == 2 && !strcmp(argv[1], "--dynamic-kick-cancel-only")) {
		test_dynamic_kick_and_cancel(kvm_fd);
		close(kvm_fd);
		return 0;
	}

	test_cross_vm_feature_dependencies(kvm_fd);
	test_dynamic_dispatch_uapi_layout();
	test_dynamic_dispatch_mapping(kvm_fd);
	test_create_empty_domain(kvm_fd);
	test_one_capsule_run_and_legacy_restore(kvm_fd);
	test_strict_cpu_placement(kvm_fd);
	test_rejects_unsupported_x86_state(kvm_fd);
	test_many_capsules_across_vms(kvm_fd);
	test_two_executor_claim_race(kvm_fd);
	test_pause_drain_and_runner_signal(kvm_fd);
	test_attached_capsule_accepts_interrupt_before_entry(kvm_fd);
	test_fd_close_orders(kvm_fd);
	test_wrong_mm(kvm_fd, argv[0]);
	test_malformed_and_stale_requests(kvm_fd);
	test_deterministic_malformed_fuzz(kvm_fd);
	test_same_vm_single_step_trace(kvm_fd);
	test_trace_validation_and_cross_vm_rejection(kvm_fd);
	test_cross_vm_single_step_trace(kvm_fd);
	test_cross_vm_state_and_seeded_traces(kvm_fd);
	test_base_only_domain_rejects_trace(kvm_fd);
	test_trace_stale_and_current_owner_rejection(kvm_fd);
	test_trace_conservative_exits(kvm_fd);
	test_cross_vm_conservative_exits(kvm_fd);
	test_cross_vm_memslot_update(kvm_fd);
	test_trace_target_contention(kvm_fd, false);
	test_trace_target_contention(kvm_fd, true);
	test_trace_signal_releases_references(kvm_fd, false);
	test_trace_signal_releases_references(kvm_fd, true);
	test_halted_trace_pause_and_drain(kvm_fd);
	test_dynamic_kick_and_cancel(kvm_fd);
	test_dynamic_ring_backpressure_and_corruption(kvm_fd);
	test_dynamic_synchronous_exits(kvm_fd);
	test_sync_domain_close_pending(kvm_fd, false);
	test_sync_domain_close_pending(kvm_fd, true);
	test_dynamic_cross_vm_seeded_trace(kvm_fd);
	test_dynamic_two_executor_migration(kvm_fd);
	close(kvm_fd);
	return 0;
}
