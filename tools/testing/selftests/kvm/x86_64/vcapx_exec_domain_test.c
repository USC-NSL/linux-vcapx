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
#include <sys/wait.h>
#include <unistd.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"

static uint64_t fuzz_state = 0x8d26f31b9c47a5e1ULL;

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

static void guest_two_exits(void)
{
	GUEST_SYNC(1);
	GUEST_DONE();
}

static uint64_t trace_counts[2];
static uint64_t trace_state_errors[2];

static void guest_single_step_trace(uint64_t id)
{
	register uint64_t signature asm("r12") = 0x5a5a000000000000ULL | id;
	const uint64_t expected = signature;

	for (;;) {
		WRITE_ONCE(trace_counts[id], READ_ONCE(trace_counts[id]) + 1);
		asm volatile("pause" : "+r"(signature) : : "memory");
		if (signature != expected)
			WRITE_ONCE(trace_state_errors[id], signature);
	}
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
	uint64_t *counts, *errors;
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
	counts = addr_gva2hva(vm, (vm_vaddr_t)trace_counts);
	errors = addr_gva2hva(vm, (vm_vaddr_t)trace_state_errors);
	memset(counts, 0, sizeof(trace_counts));
	memset(errors, 0, sizeof(trace_state_errors));

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

	control_domain(domain_fd, KVM_EXEC_PAUSE);
	control_domain(domain_fd, KVM_EXEC_DRAIN);
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

static void guest_trace_hlt(void)
{
	asm volatile("hlt");
	GUEST_DONE();
}

static void guest_trace_io(void)
{
	GUEST_SYNC(1);
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
	test_trace_stops_on_non_debug_exit(kvm_fd, guest_trace_hlt,
					   KVM_EXIT_HLT);
	test_trace_stops_on_non_debug_exit(kvm_fd, guest_trace_io,
					   KVM_EXIT_IO);
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
				    KVM_EXEC_FEATURE_INTRA_VM_CHAIN)) ==
		     (KVM_EXEC_FEATURE_BASE_OBJECTS |
		      KVM_EXEC_FEATURE_INTRA_VM_CHAIN));

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
	test_base_only_domain_rejects_trace(kvm_fd);
	test_trace_conservative_exits(kvm_fd);
	close(kvm_fd);
	return 0;
}
