// SPDX-License-Identifier: GPL-2.0-only
#include <linux/anon_inodes.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/kref.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/xarray.h>

#define KVM_EXEC_SUPPORTED_FEATURES \
	(KVM_EXEC_FEATURE_BASE_OBJECTS | KVM_EXEC_FEATURE_INTRA_VM_CHAIN | \
	 KVM_EXEC_FEATURE_CROSS_VM_CHAIN)

struct kvm_exec_domain;
struct kvm_exec_executor;

struct kvm_exec_capsule {
	struct kvm_exec_domain *domain;
	struct file *vcpu_file;
	struct kvm_vcpu *vcpu;
	struct kvm_exec_executor *owner;
	u64 capsule_id;
	u64 lifecycle_generation;
	u32 trace_refs;
	bool running;
};

struct kvm_exec_executor {
	struct kvm_exec_domain *domain;
	struct kvm_exec_capsule *current_capsule;
	struct list_head node;
	/* Serializes commands submitted through this executor fd. */
	struct mutex run_lock;
	u64 generation;
	u64 cookie;
	u64 last_request_sequence;
	u32 requested_cpu;
	u32 flags;
	bool listed;
};

struct kvm_exec_domain {
	struct kref kref;
	struct mm_struct *mm;
	const struct cred *cred;
	/* Protects object maps, ownership, lifecycle state, and counts. */
	struct mutex lock;
	struct xarray capsules;
	struct list_head executors;
	wait_queue_head_t drain_wait;
	atomic_t active_runs;
	u64 generation;
	u64 negotiated_features;
	u32 max_capsules;
	u32 max_executors;
	u32 nr_capsule_slots;
	u32 nr_attached;
	u32 nr_executors;
	bool paused;
	bool stopping;
};

static atomic64_t kvm_exec_domain_generation = ATOMIC64_INIT(0);
static atomic64_t kvm_exec_executor_generation = ATOMIC64_INIT(0);

static const struct file_operations kvm_exec_domain_fops;
static const struct file_operations kvm_exec_executor_fops;

bool __weak kvm_arch_vcpu_exec_domain_supported(struct kvm_vcpu *vcpu)
{
	return false;
}

static u64 kvm_exec_next_generation(atomic64_t *counter)
{
	u64 generation = atomic64_inc_return(counter);

	if (!generation)
		generation = atomic64_inc_return(counter);
	return generation;
}

static int kvm_exec_domain_access(struct kvm_exec_domain *domain)
{
	if (domain->mm != current->mm)
		return -EIO;
	if (domain->cred != current_cred())
		return -EACCES;
	return 0;
}

bool kvm_exec_domain_vcpu_ioctl_allowed(struct kvm_vcpu *vcpu,
					unsigned int ioctl)
{
	struct kvm_exec_capsule *capsule = vcpu->exec_capsule;

	if (!capsule || READ_ONCE(capsule->running))
		return false;

	return ioctl == KVM_INTERRUPT || READ_ONCE(capsule->domain->paused);
}

static bool kvm_exec_control_valid(struct kvm_exec_domain_control *control)
{
	return control->size == sizeof(*control) && !control->flags &&
	       !memchr_inv(control->reserved, 0, sizeof(control->reserved));
}

static void kvm_exec_kick_running_locked(struct kvm_exec_domain *domain)
{
	struct kvm_exec_capsule *capsule;
	unsigned long index;

	xa_for_each(&domain->capsules, index, capsule) {
		if (!capsule->vcpu || !capsule->running)
			continue;
		kvm_make_request(KVM_REQ_EXEC_DOMAIN_EXIT, capsule->vcpu);
		/* Break KVM's halt wait so x86 can consume the exit request. */
		kvm_make_request(KVM_REQ_UNBLOCK, capsule->vcpu);
		kvm_vcpu_kick(capsule->vcpu);
	}
}

static void kvm_exec_release_ownership_locked(struct kvm_exec_domain *domain)
{
	struct kvm_exec_executor *executor;
	struct kvm_exec_capsule *capsule;
	unsigned long index;

	list_for_each_entry(executor, &domain->executors, node)
		executor->current_capsule = NULL;
	xa_for_each(&domain->capsules, index, capsule) {
		if (!capsule->running)
			capsule->owner = NULL;
	}
}

static int kvm_exec_domain_pause(struct kvm_exec_domain *domain)
{
	int ret = 0;

	mutex_lock(&domain->lock);
	if (domain->stopping) {
		ret = -ESHUTDOWN;
	} else {
		domain->paused = true;
		kvm_exec_kick_running_locked(domain);
	}
	mutex_unlock(&domain->lock);
	return ret;
}

static int kvm_exec_domain_drain(struct kvm_exec_domain *domain)
{
	int ret;

	if (!READ_ONCE(domain->paused))
		return -EBUSY;

	ret = wait_event_interruptible(domain->drain_wait,
				       !atomic_read(&domain->active_runs));
	if (ret)
		return ret;

	mutex_lock(&domain->lock);
	if (!domain->paused) {
		ret = -EBUSY;
	} else {
		kvm_exec_release_ownership_locked(domain);
		ret = 0;
	}
	mutex_unlock(&domain->lock);
	return ret;
}

static int kvm_exec_domain_resume(struct kvm_exec_domain *domain)
{
	struct kvm_exec_capsule *capsule;
	unsigned long index;
	int ret = 0;

	mutex_lock(&domain->lock);
	if (domain->stopping) {
		ret = -ESHUTDOWN;
	} else if (!domain->paused || atomic_read(&domain->active_runs)) {
		ret = -EBUSY;
	} else {
		xa_for_each(&domain->capsules, index, capsule) {
			if (capsule->vcpu)
				kvm_clear_request(KVM_REQ_EXEC_DOMAIN_EXIT,
						  capsule->vcpu);
		}
		domain->paused = false;
	}
	mutex_unlock(&domain->lock);
	return ret;
}

static int kvm_exec_attach_vcpu(struct kvm_exec_domain *domain,
				void __user *argp)
{
	struct kvm_exec_attach_vcpu attach;
	struct kvm_exec_capsule *capsule, *new_capsule = NULL;
	struct file *vcpu_file;
	struct kvm_vcpu *vcpu;
	bool inserted_slot = false;
	int ret;

	if (copy_from_user(&attach, argp, sizeof(attach)))
		return -EFAULT;
	if (attach.size != sizeof(attach) || attach.flags || attach.reserved0 ||
	    !attach.capsule_id || !attach.lifecycle_generation ||
	    attach.capsule_id > ULONG_MAX ||
	    memchr_inv(attach.reserved, 0, sizeof(attach.reserved)))
		return -EINVAL;

	vcpu = kvm_vcpu_from_fd(attach.vcpu_fd, &vcpu_file);
	if (IS_ERR(vcpu))
		return PTR_ERR(vcpu);
	if (vcpu->kvm->mm != domain->mm) {
		ret = -EIO;
		goto out_file;
	}

	mutex_lock(&domain->lock);
	if (domain->stopping) {
		ret = -ESHUTDOWN;
		goto out_unlock;
	}

	capsule = xa_load(&domain->capsules, attach.capsule_id);
	if (capsule && capsule->vcpu) {
		ret = -EEXIST;
		goto out_unlock;
	}
	if (capsule && attach.lifecycle_generation <=
		       capsule->lifecycle_generation) {
		ret = -ESTALE;
		goto out_unlock;
	}
	if (!capsule) {
		if (domain->nr_capsule_slots == domain->max_capsules) {
			ret = -ENOSPC;
			goto out_unlock;
		}
		new_capsule = kzalloc(sizeof(*new_capsule), GFP_KERNEL_ACCOUNT);
		if (!new_capsule) {
			ret = -ENOMEM;
			goto out_unlock;
		}
		new_capsule->domain = domain;
		new_capsule->capsule_id = attach.capsule_id;
		ret = xa_err(xa_store(&domain->capsules, attach.capsule_id,
				      new_capsule, GFP_KERNEL_ACCOUNT));
		if (ret)
			goto out_unlock;
		domain->nr_capsule_slots++;
		inserted_slot = true;
		capsule = new_capsule;
		new_capsule = NULL;
	}

	if (!mutex_trylock(&vcpu->mutex)) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (vcpu->exec_capsule) {
		ret = -EBUSY;
	} else if (!kvm_arch_vcpu_exec_domain_supported(vcpu)) {
		ret = -EOPNOTSUPP;
	} else {
		capsule->vcpu_file = vcpu_file;
		capsule->vcpu = vcpu;
		capsule->lifecycle_generation = attach.lifecycle_generation;
		vcpu->exec_capsule = capsule;
		domain->nr_attached++;
		ret = 0;
	}
	mutex_unlock(&vcpu->mutex);
	if (!ret)
		vcpu_file = NULL;

out_unlock:
	if (ret && inserted_slot) {
		xa_erase(&domain->capsules, attach.capsule_id);
		domain->nr_capsule_slots--;
		kfree(capsule);
	}
	mutex_unlock(&domain->lock);
	kfree(new_capsule);
out_file:
	if (vcpu_file)
		fput(vcpu_file);
	return ret;
}

static int kvm_exec_detach_vcpu(struct kvm_exec_domain *domain,
				void __user *argp)
{
	struct kvm_exec_detach_vcpu detach;
	struct kvm_exec_capsule *capsule;
	struct file *vcpu_file = NULL;
	int ret = 0;

	if (copy_from_user(&detach, argp, sizeof(detach)))
		return -EFAULT;
	if (detach.size != sizeof(detach) || detach.flags ||
	    !detach.capsule_id || !detach.lifecycle_generation ||
	    detach.capsule_id > ULONG_MAX ||
	    memchr_inv(detach.reserved, 0, sizeof(detach.reserved)))
		return -EINVAL;

	mutex_lock(&domain->lock);
	if (domain->stopping) {
		ret = -ESHUTDOWN;
		goto out;
	}
	capsule = xa_load(&domain->capsules, detach.capsule_id);
	if (!capsule || !capsule->vcpu) {
		ret = -ENOENT;
		goto out;
	}
	if (capsule->lifecycle_generation != detach.lifecycle_generation) {
		ret = -ESTALE;
		goto out;
	}
	if (capsule->owner || capsule->running || capsule->trace_refs) {
		ret = -EBUSY;
		goto out;
	}

	mutex_lock(&capsule->vcpu->mutex);
	capsule->vcpu->exec_capsule = NULL;
	mutex_unlock(&capsule->vcpu->mutex);
	vcpu_file = capsule->vcpu_file;
	capsule->vcpu_file = NULL;
	capsule->vcpu = NULL;
	domain->nr_attached--;
out:
	mutex_unlock(&domain->lock);
	if (vcpu_file)
		fput(vcpu_file);
	return ret;
}

static void kvm_exec_domain_free(struct kref *kref)
{
	struct kvm_exec_domain *domain =
		container_of(kref, struct kvm_exec_domain, kref);
	struct kvm_exec_capsule *capsule;
	unsigned long index;

	xa_for_each(&domain->capsules, index, capsule)
		kfree(capsule);
	xa_destroy(&domain->capsules);
	put_cred(domain->cred);
	mmdrop(domain->mm);
	kfree(domain);
}

static int kvm_exec_executor_release(struct inode *inode, struct file *file)
{
	struct kvm_exec_executor *executor = file->private_data;
	struct kvm_exec_domain *domain = executor->domain;

	mutex_lock(&domain->lock);
	if (executor->current_capsule && !executor->current_capsule->running) {
		executor->current_capsule->owner = NULL;
		executor->current_capsule = NULL;
	}
	if (executor->listed) {
		list_del(&executor->node);
		domain->nr_executors--;
		executor->listed = false;
	}
	mutex_unlock(&domain->lock);

	kref_put(&domain->kref, kvm_exec_domain_free);
	kfree(executor);
	return 0;
}

static int kvm_exec_create_executor(struct kvm_exec_domain *domain,
				    void __user *argp)
{
	struct kvm_exec_create_executor create;
	struct kvm_exec_executor *executor;
	struct file *file;
	int fd, ret;

	if (copy_from_user(&create, argp, sizeof(create)))
		return -EFAULT;
	if (create.size != sizeof(create) ||
	    create.flags & ~KVM_EXECUTOR_F_STRICT_CPU || create.reserved0 ||
	    memchr_inv(create.reserved, 0, sizeof(create.reserved)) ||
	    ((create.flags & KVM_EXECUTOR_F_STRICT_CPU) &&
	     create.requested_cpu == KVM_EXEC_CPU_ANY) ||
	    (create.requested_cpu != KVM_EXEC_CPU_ANY &&
	     (create.requested_cpu >= nr_cpu_ids ||
	      !cpu_possible(create.requested_cpu))))
		return -EINVAL;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;
	executor = kzalloc(sizeof(*executor), GFP_KERNEL_ACCOUNT);
	if (!executor) {
		put_unused_fd(fd);
		return -ENOMEM;
	}

	executor->domain = domain;
	executor->generation =
		kvm_exec_next_generation(&kvm_exec_executor_generation);
	executor->cookie = create.executor_cookie;
	executor->requested_cpu = create.requested_cpu;
	executor->flags = create.flags;
	mutex_init(&executor->run_lock);
	INIT_LIST_HEAD(&executor->node);
	kref_get(&domain->kref);

	file = anon_inode_getfile("kvm-executor", &kvm_exec_executor_fops,
				  executor, O_RDWR);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		kref_put(&domain->kref, kvm_exec_domain_free);
		kfree(executor);
		put_unused_fd(fd);
		return ret;
	}

	mutex_lock(&domain->lock);
	if (domain->stopping) {
		ret = -ESHUTDOWN;
	} else if (domain->nr_executors == domain->max_executors) {
		ret = -ENOSPC;
	} else {
		list_add_tail(&executor->node, &domain->executors);
		domain->nr_executors++;
		executor->listed = true;
		ret = 0;
	}
	mutex_unlock(&domain->lock);
	if (ret)
		goto out_file;

	create.executor_generation = executor->generation;
	if (copy_to_user(argp, &create, sizeof(create))) {
		ret = -EFAULT;
		goto out_file;
	}

	fd_install(fd, file);
	return fd;

out_file:
	fput(file);
	put_unused_fd(fd);
	return ret;
}

static void kvm_exec_abort_run(struct kvm_exec_executor *executor,
			       struct kvm_exec_capsule *capsule,
			       bool release_claim)
{
	struct kvm_exec_domain *domain = executor->domain;

	mutex_lock(&domain->lock);
	capsule->running = false;
	if (release_claim && capsule->owner == executor) {
		capsule->owner = NULL;
		executor->current_capsule = NULL;
	}
	atomic_dec(&domain->active_runs);
	mutex_unlock(&domain->lock);
	wake_up_all(&domain->drain_wait);
}

static long kvm_exec_run(struct kvm_exec_executor *executor, void __user *argp)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_capsule *capsule;
	struct kvm_exec_run run;
	bool new_claim = false;
	u32 initial_cpu, final_cpu;
	int ret;

	if (copy_from_user(&run, argp, sizeof(run)))
		return -EFAULT;
	if (run.size != sizeof(run) || run.flags || !run.request_sequence ||
	    !run.target_capsule_id || !run.target_lifecycle_generation ||
	    run.target_capsule_id > ULONG_MAX ||
	    memchr_inv(run.reserved, 0, sizeof(run.reserved)))
		return -EINVAL;
	ret = kvm_exec_domain_access(domain);
	if (ret)
		return ret;
	if (mutex_lock_killable(&executor->run_lock))
		return -EINTR;

	if (run.domain_generation != domain->generation ||
	    run.executor_generation != executor->generation ||
	    run.request_sequence <= executor->last_request_sequence) {
		ret = -ESTALE;
		goto out_executor;
	}

	initial_cpu = get_cpu();
	put_cpu();
	if ((executor->flags & KVM_EXECUTOR_F_STRICT_CPU) &&
	    initial_cpu != executor->requested_cpu) {
		ret = -EXDEV;
		goto out_executor;
	}

	mutex_lock(&domain->lock);
	if (domain->stopping) {
		ret = -ESHUTDOWN;
		goto out_domain;
	}
	if (domain->paused) {
		ret = -EBUSY;
		goto out_domain;
	}
	capsule = xa_load(&domain->capsules, run.target_capsule_id);
	if (!capsule || !capsule->vcpu) {
		ret = -ENOENT;
		goto out_domain;
	}
	if (capsule->lifecycle_generation !=
	    run.target_lifecycle_generation) {
		ret = -ESTALE;
		goto out_domain;
	}
	if ((executor->current_capsule && executor->current_capsule != capsule) ||
	    (capsule->owner && capsule->owner != executor) || capsule->running) {
		ret = -EBUSY;
		goto out_domain;
	}
	if (!capsule->owner) {
		capsule->owner = executor;
		executor->current_capsule = capsule;
		new_claim = true;
	}
	capsule->running = true;
	atomic_inc(&domain->active_runs);
	executor->last_request_sequence = run.request_sequence;
	mutex_unlock(&domain->lock);

	if (mutex_lock_killable(&capsule->vcpu->mutex)) {
		ret = -EINTR;
		kvm_exec_abort_run(executor, capsule, new_claim);
		goto out_executor;
	}
	if (READ_ONCE(domain->stopping) || READ_ONCE(domain->paused)) {
		ret = -EBUSY;
		mutex_unlock(&capsule->vcpu->mutex);
		kvm_exec_abort_run(executor, capsule, new_claim);
		goto out_executor;
	}
	if (capsule->vcpu->exec_capsule != capsule ||
	    !kvm_arch_vcpu_exec_domain_supported(capsule->vcpu)) {
		ret = -EOPNOTSUPP;
		mutex_unlock(&capsule->vcpu->mutex);
		kvm_exec_abort_run(executor, capsule, new_claim);
		goto out_executor;
	}

	ret = kvm_vcpu_run(capsule->vcpu);
	final_cpu = get_cpu();
	put_cpu();
	run.run_result = ret;
	run.vcpu_exit_reason = capsule->vcpu->run->exit_reason;
	mutex_unlock(&capsule->vcpu->mutex);

	kvm_exec_abort_run(executor, capsule, false);
	if (READ_ONCE(domain->stopping))
		run.return_reason = KVM_EXEC_RETURN_DOMAIN_STOPPING;
	else if (READ_ONCE(domain->paused))
		run.return_reason = KVM_EXEC_RETURN_DOMAIN_PAUSED;
	else if ((executor->flags & KVM_EXECUTOR_F_STRICT_CPU) &&
		 final_cpu != executor->requested_cpu)
		run.return_reason = KVM_EXEC_RETURN_CPU_MIGRATED;
	else if (ret == -EINTR)
		run.return_reason = KVM_EXEC_RETURN_SIGNAL;
	else
		run.return_reason = KVM_EXEC_RETURN_VCPU_EXIT;
	run.current_cpu = final_cpu;
	run.owned_capsule_id = capsule->capsule_id;
	run.owned_lifecycle_generation = capsule->lifecycle_generation;
	memset(run.reserved, 0, sizeof(run.reserved));
	ret = copy_to_user(argp, &run, sizeof(run)) ? -EFAULT : 0;
	goto out_executor;

out_domain:
	mutex_unlock(&domain->lock);
out_executor:
	mutex_unlock(&executor->run_lock);
	return ret;
}

static void
kvm_exec_trace_put_refs_locked(struct kvm_exec_capsule **capsules, u32 nr_capsules)
{
	u32 i;

	for (i = 0; i < nr_capsules; i++) {
		if (WARN_ON_ONCE(!capsules[i]->trace_refs))
			continue;
		capsules[i]->trace_refs--;
	}
}

static long kvm_exec_run_trace(struct kvm_exec_executor *executor,
			       void __user *argp)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_trace_entry *entries;
	struct kvm_exec_capsule **capsules;
	struct kvm_exec_capsule *capsule, *next;
	struct kvm_exec_run_trace trace;
	struct kvm *trace_kvm = NULL;
	u64 total_steps, step;
	u64 handoff_start, handoff_end;
	u32 initial_cpu, final_cpu, i;
	bool active = false;
	int run_ret, ret;

	if (copy_from_user(&trace, argp, sizeof(trace)))
		return -EFAULT;
	if (trace.size != sizeof(trace) || trace.flags ||
	    !trace.request_sequence || !trace.nr_entries ||
	    trace.nr_entries > KVM_EXEC_TRACE_MAX_ENTRIES ||
	    !trace.repeat_count ||
	    memchr_inv(trace.reserved, 0, sizeof(trace.reserved)))
		return trace.nr_entries > KVM_EXEC_TRACE_MAX_ENTRIES ?
			-E2BIG : -EINVAL;
	total_steps = (u64)trace.nr_entries * trace.repeat_count;
	if (total_steps > KVM_EXEC_TRACE_MAX_STEPS)
		return -E2BIG;

	ret = kvm_exec_domain_access(domain);
	if (ret)
		return ret;
	if (!(domain->negotiated_features &
	      KVM_EXEC_FEATURE_INTRA_VM_CHAIN))
		return -EOPNOTSUPP;

	entries = memdup_array_user(u64_to_user_ptr(trace.entries),
				    trace.nr_entries, sizeof(*entries));
	if (IS_ERR(entries))
		return PTR_ERR(entries);
	capsules = kcalloc(trace.nr_entries, sizeof(*capsules),
			   GFP_KERNEL_ACCOUNT);
	if (!capsules) {
		ret = -ENOMEM;
		goto out_entries;
	}

	for (i = 0; i < trace.nr_entries; i++) {
		if (!entries[i].capsule_id ||
		    !entries[i].lifecycle_generation || entries[i].reserved ||
		    entries[i].capsule_id > ULONG_MAX) {
			ret = -EINVAL;
			goto out_capsules;
		}
	}

	if (mutex_lock_killable(&executor->run_lock)) {
		ret = -EINTR;
		goto out_capsules;
	}
	if (trace.domain_generation != domain->generation ||
	    trace.executor_generation != executor->generation ||
	    trace.request_sequence <= executor->last_request_sequence) {
		ret = -ESTALE;
		goto out_executor;
	}

	initial_cpu = get_cpu();
	put_cpu();
	final_cpu = initial_cpu;
	if ((executor->flags & KVM_EXECUTOR_F_STRICT_CPU) &&
	    initial_cpu != executor->requested_cpu) {
		ret = -EXDEV;
		goto out_executor;
	}

	mutex_lock(&domain->lock);
	if (domain->stopping) {
		ret = -ESHUTDOWN;
		goto out_domain;
	}
	if (domain->paused) {
		ret = -EBUSY;
		goto out_domain;
	}

	for (i = 0; i < trace.nr_entries; i++) {
		capsule = xa_load(&domain->capsules, entries[i].capsule_id);
		if (!capsule || !capsule->vcpu) {
			ret = -ENOENT;
			goto out_domain;
		}
		if (capsule->lifecycle_generation !=
		    entries[i].lifecycle_generation) {
			ret = -ESTALE;
			goto out_domain;
		}
		if (!trace_kvm) {
			trace_kvm = capsule->vcpu->kvm;
		} else if (trace_kvm != capsule->vcpu->kvm &&
			   !(domain->negotiated_features &
			     KVM_EXEC_FEATURE_CROSS_VM_CHAIN)) {
			ret = -EXDEV;
			goto out_domain;
		}
		if ((capsule->vcpu->guest_debug &
		     (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP)) !=
		    (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP)) {
			ret = -EINVAL;
			goto out_domain;
		}
		if ((capsule->owner &&
		     (capsule->owner != executor ||
		      executor->current_capsule != capsule)) ||
		    capsule->running) {
			ret = -EBUSY;
			goto out_domain;
		}
		capsules[i] = capsule;
	}

	capsule = capsules[0];
	if ((executor->current_capsule &&
	     executor->current_capsule != capsule) ||
	    (capsule->owner && capsule->owner != executor)) {
		ret = -EBUSY;
		goto out_domain;
	}
	for (i = 0; i < trace.nr_entries; i++)
		capsules[i]->trace_refs++;
	if (!capsule->owner) {
		capsule->owner = executor;
		executor->current_capsule = capsule;
	}
	capsule->running = true;
	atomic_inc(&domain->active_runs);
	active = true;
	executor->last_request_sequence = trace.request_sequence;
	mutex_unlock(&domain->lock);

	trace.return_reason = 0;
	trace.run_result = 0;
	trace.vcpu_exit_reason = 0;
	trace.current_cpu = initial_cpu;
	trace.owned_capsule_id = capsule->capsule_id;
	trace.owned_lifecycle_generation = capsule->lifecycle_generation;
	trace.completed_steps = 0;
	trace.switch_count = 0;
	trace.first_switch_ns = 0;
	trace.last_switch_ns = 0;
	trace.ownership_handoff_ns = 0;

	for (step = 0; step < total_steps; step++) {
		final_cpu = get_cpu();
		put_cpu();
		trace.current_cpu = final_cpu;
		if ((executor->flags & KVM_EXECUTOR_F_STRICT_CPU) &&
		    final_cpu != executor->requested_cpu) {
			trace.return_reason = KVM_EXEC_RETURN_CPU_MIGRATED;
			trace.run_result = -EXDEV;
			goto finish_run;
		}

		capsule = executor->current_capsule;
		if (mutex_lock_killable(&capsule->vcpu->mutex)) {
			trace.return_reason = KVM_EXEC_RETURN_SIGNAL;
			trace.run_result = -EINTR;
			goto finish_run;
		}
		if (READ_ONCE(domain->stopping) || READ_ONCE(domain->paused)) {
			trace.return_reason = READ_ONCE(domain->stopping) ?
				KVM_EXEC_RETURN_DOMAIN_STOPPING :
				KVM_EXEC_RETURN_DOMAIN_PAUSED;
			trace.run_result = -EINTR;
			mutex_unlock(&capsule->vcpu->mutex);
			goto finish_run;
		}
		if (capsule->vcpu->exec_capsule != capsule ||
		    !kvm_arch_vcpu_exec_domain_supported(capsule->vcpu)) {
			trace.return_reason = KVM_EXEC_RETURN_VCPU_EXIT;
			trace.run_result = -EOPNOTSUPP;
			mutex_unlock(&capsule->vcpu->mutex);
			goto finish_run;
		}

		run_ret = kvm_vcpu_run(capsule->vcpu);
		final_cpu = get_cpu();
		put_cpu();
		trace.run_result = run_ret;
		trace.vcpu_exit_reason = capsule->vcpu->run->exit_reason;
		trace.current_cpu = final_cpu;
		mutex_unlock(&capsule->vcpu->mutex);

		mutex_lock(&domain->lock);
		capsule->running = false;
		if (domain->stopping) {
			trace.return_reason = KVM_EXEC_RETURN_DOMAIN_STOPPING;
			goto finish_locked;
		}
		if (domain->paused) {
			trace.return_reason = KVM_EXEC_RETURN_DOMAIN_PAUSED;
			goto finish_locked;
		}
		if ((executor->flags & KVM_EXECUTOR_F_STRICT_CPU) &&
		    final_cpu != executor->requested_cpu) {
			trace.return_reason = KVM_EXEC_RETURN_CPU_MIGRATED;
			goto finish_locked;
		}
		if (run_ret == -EINTR) {
			trace.return_reason = KVM_EXEC_RETURN_SIGNAL;
			goto finish_locked;
		}
		if (run_ret || trace.vcpu_exit_reason != KVM_EXIT_DEBUG) {
			trace.return_reason = KVM_EXEC_RETURN_VCPU_EXIT;
			goto finish_locked;
		}

		trace.completed_steps++;
		if (step + 1 == total_steps) {
			trace.return_reason = KVM_EXEC_RETURN_TRACE_COMPLETE;
			goto finish_locked;
		}

		next = capsules[(step + 1) % trace.nr_entries];
		if (next == capsule) {
			capsule->running = true;
			mutex_unlock(&domain->lock);
			continue;
		}

		handoff_start = ktime_get_ns();
		if (next->owner || next->running) {
			trace.return_reason = KVM_EXEC_RETURN_TRACE_TARGET_BUSY;
			trace.run_result = -EBUSY;
			goto finish_locked;
		}
		capsule->owner = NULL;
		next->owner = executor;
		executor->current_capsule = next;
		next->running = true;
		handoff_end = ktime_get_ns();
		trace.switch_count++;
		if (!trace.first_switch_ns)
			trace.first_switch_ns = handoff_end;
		trace.last_switch_ns = handoff_end;
		trace.ownership_handoff_ns += handoff_end - handoff_start;
		mutex_unlock(&domain->lock);
	}

finish_run:
	mutex_lock(&domain->lock);
	capsule = executor->current_capsule;
	if (capsule && capsule->running)
		capsule->running = false;
finish_locked:
	capsule = executor->current_capsule;
	if (capsule) {
		trace.owned_capsule_id = capsule->capsule_id;
		trace.owned_lifecycle_generation =
			capsule->lifecycle_generation;
	}
	if (active) {
		kvm_exec_trace_put_refs_locked(capsules, trace.nr_entries);
		atomic_dec(&domain->active_runs);
	}
	mutex_unlock(&domain->lock);
	wake_up_all(&domain->drain_wait);
	memset(trace.reserved, 0, sizeof(trace.reserved));
	ret = copy_to_user(argp, &trace, sizeof(trace)) ? -EFAULT : 0;
	goto out_executor;

out_domain:
	mutex_unlock(&domain->lock);
out_executor:
	mutex_unlock(&executor->run_lock);
out_capsules:
	kfree(capsules);
out_entries:
	kfree(entries);
	return ret;
}

static long kvm_exec_executor_ioctl(struct file *file, unsigned int ioctl,
				    unsigned long arg)
{
	struct kvm_exec_executor *executor = file->private_data;

	if (_IOC_TYPE(ioctl) != KVMIO)
		return -EINVAL;
	if (ioctl == KVM_EXEC_RUN)
		return kvm_exec_run(executor, (void __user *)arg);
	if (ioctl == KVM_EXEC_RUN_TRACE)
		return kvm_exec_run_trace(executor, (void __user *)arg);
	return -ENOTTY;
}

static const struct file_operations kvm_exec_executor_fops = {
	.owner = THIS_MODULE,
	.release = kvm_exec_executor_release,
	.unlocked_ioctl = kvm_exec_executor_ioctl,
	.llseek = noop_llseek,
#ifdef CONFIG_COMPAT
	.compat_ioctl = kvm_exec_executor_ioctl,
#endif
};

static void kvm_exec_domain_stop(struct kvm_exec_domain *domain)
{
	struct kvm_exec_capsule *capsule;
	struct file *vcpu_file;
	unsigned long index;

	mutex_lock(&domain->lock);
	domain->stopping = true;
	domain->paused = true;
	kvm_exec_kick_running_locked(domain);
	mutex_unlock(&domain->lock);

	wait_event(domain->drain_wait, !atomic_read(&domain->active_runs));

	mutex_lock(&domain->lock);
	kvm_exec_release_ownership_locked(domain);
	xa_for_each(&domain->capsules, index, capsule) {
		if (!capsule->vcpu)
			continue;
		mutex_lock(&capsule->vcpu->mutex);
		capsule->vcpu->exec_capsule = NULL;
		mutex_unlock(&capsule->vcpu->mutex);
		vcpu_file = capsule->vcpu_file;
		capsule->vcpu_file = NULL;
		capsule->vcpu = NULL;
		domain->nr_attached--;
		fput(vcpu_file);
	}
	mutex_unlock(&domain->lock);
}

static int kvm_exec_domain_release(struct inode *inode, struct file *file)
{
	struct kvm_exec_domain *domain = file->private_data;

	kvm_exec_domain_stop(domain);
	kref_put(&domain->kref, kvm_exec_domain_free);
	return 0;
}

static long kvm_exec_domain_ioctl(struct file *file, unsigned int ioctl,
				  unsigned long arg)
{
	struct kvm_exec_domain *domain = file->private_data;
	struct kvm_exec_domain_control control;
	void __user *argp = (void __user *)arg;
	int ret;

	if (_IOC_TYPE(ioctl) != KVMIO)
		return -EINVAL;
	ret = kvm_exec_domain_access(domain);
	if (ret)
		return ret;

	switch (ioctl) {
	case KVM_EXEC_ATTACH_VCPU:
		return kvm_exec_attach_vcpu(domain, argp);
	case KVM_EXEC_DETACH_VCPU:
		return kvm_exec_detach_vcpu(domain, argp);
	case KVM_EXEC_CREATE_EXECUTOR:
		return kvm_exec_create_executor(domain, argp);
	case KVM_EXEC_PAUSE:
	case KVM_EXEC_RESUME:
	case KVM_EXEC_DRAIN:
		if (copy_from_user(&control, argp, sizeof(control)))
			return -EFAULT;
		if (!kvm_exec_control_valid(&control))
			return -EINVAL;
		if (ioctl == KVM_EXEC_PAUSE)
			return kvm_exec_domain_pause(domain);
		if (ioctl == KVM_EXEC_RESUME)
			return kvm_exec_domain_resume(domain);
		return kvm_exec_domain_drain(domain);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations kvm_exec_domain_fops = {
	.owner = THIS_MODULE,
	.release = kvm_exec_domain_release,
	.unlocked_ioctl = kvm_exec_domain_ioctl,
	.llseek = noop_llseek,
#ifdef CONFIG_COMPAT
	.compat_ioctl = kvm_exec_domain_ioctl,
#endif
};

int kvm_dev_ioctl_create_exec_domain(void __user *argp)
{
	struct kvm_exec_domain_create create;
	struct kvm_exec_domain *domain;
	struct file *file;
	int fd;

	if (!IS_ENABLED(CONFIG_X86_64))
		return -EOPNOTSUPP;
	if (copy_from_user(&create, argp, sizeof(create)))
		return -EFAULT;
	if (create.size != sizeof(create) || create.flags ||
	    !create.max_capsules || !create.max_executors ||
	    create.max_capsules > U16_MAX || create.max_executors > U16_MAX ||
	    !(create.requested_features & KVM_EXEC_FEATURE_BASE_OBJECTS) ||
	    create.requested_features & ~KVM_EXEC_SUPPORTED_FEATURES ||
	    ((create.requested_features & KVM_EXEC_FEATURE_CROSS_VM_CHAIN) &&
	     !(create.requested_features & KVM_EXEC_FEATURE_INTRA_VM_CHAIN)) ||
	    memchr_inv(create.reserved, 0, sizeof(create.reserved)))
		return -EINVAL;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;
	domain = kzalloc(sizeof(*domain), GFP_KERNEL_ACCOUNT);
	if (!domain) {
		put_unused_fd(fd);
		return -ENOMEM;
	}

	kref_init(&domain->kref);
	domain->mm = current->mm;
	mmgrab(domain->mm);
	domain->cred = get_current_cred();
	mutex_init(&domain->lock);
	xa_init(&domain->capsules);
	INIT_LIST_HEAD(&domain->executors);
	init_waitqueue_head(&domain->drain_wait);
	atomic_set(&domain->active_runs, 0);
	domain->generation =
		kvm_exec_next_generation(&kvm_exec_domain_generation);
	domain->negotiated_features = create.requested_features;
	domain->max_capsules = create.max_capsules;
	domain->max_executors = create.max_executors;

	file = anon_inode_getfile("kvm-exec-domain", &kvm_exec_domain_fops,
				  domain, O_RDWR);
	if (IS_ERR(file)) {
		int ret = PTR_ERR(file);

		kref_put(&domain->kref, kvm_exec_domain_free);
		put_unused_fd(fd);
		return ret;
	}

	create.negotiated_features = domain->negotiated_features;
	create.domain_generation = domain->generation;
	if (copy_to_user(argp, &create, sizeof(create))) {
		fput(file);
		put_unused_fd(fd);
		return -EFAULT;
	}

	fd_install(fd, file);
	return fd;
}
