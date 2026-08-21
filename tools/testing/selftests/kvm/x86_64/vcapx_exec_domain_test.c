// SPDX-License-Identifier: GPL-2.0-only
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

static int create_domain(int kvm_fd, uint32_t max_capsules,
			 uint32_t max_executors, uint64_t *generation)
{
	struct kvm_exec_domain_create create = {
		.size = sizeof(create),
		.max_capsules = max_capsules,
		.max_executors = max_executors,
		.requested_features = KVM_EXEC_FEATURE_BASE_OBJECTS,
	};
	int domain_fd;

	domain_fd = ioctl(kvm_fd, KVM_CREATE_EXEC_DOMAIN, &create);
	TEST_ASSERT(domain_fd >= 0,
		    KVM_IOCTL_ERROR(KVM_CREATE_EXEC_DOMAIN, domain_fd));
	TEST_ASSERT_EQ(create.negotiated_features,
		       KVM_EXEC_FEATURE_BASE_OBJECTS);
	TEST_ASSERT(create.domain_generation != 0,
		    "KVM returned a zero execution-domain generation");
	*generation = create.domain_generation;
	return domain_fd;
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

static int create_executor(int domain_fd, uint64_t cookie,
			   uint64_t *generation)
{
	struct kvm_exec_create_executor create = {
		.size = sizeof(create),
		.requested_cpu = KVM_EXEC_CPU_ANY,
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
	TEST_REQUIRE(capability == KVM_EXEC_FEATURE_BASE_OBJECTS);

	test_create_empty_domain(kvm_fd);
	test_one_capsule_run_and_legacy_restore(kvm_fd);
	test_many_capsules_across_vms(kvm_fd);
	test_two_executor_claim_race(kvm_fd);
	test_pause_drain_and_runner_signal(kvm_fd);
	test_fd_close_orders(kvm_fd);
	test_wrong_mm(kvm_fd, argv[0]);
	test_malformed_and_stale_requests(kvm_fd);
	close(kvm_fd);
	return 0;
}
