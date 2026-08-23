// SPDX-License-Identifier: GPL-2.0-only
#include <linux/anon_inodes.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/kref.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/xarray.h>

#define KVM_EXEC_SUPPORTED_FEATURES \
	(KVM_EXEC_FEATURE_BASE_OBJECTS | KVM_EXEC_FEATURE_INTRA_VM_CHAIN | \
	 KVM_EXEC_FEATURE_CROSS_VM_CHAIN | KVM_EXEC_FEATURE_DYNAMIC_DISPATCH | \
	 KVM_EXEC_FEATURE_SYNC_EXITS)

struct kvm_exec_domain;
struct kvm_exec_executor;

struct kvm_exec_exit_state {
	u64 sequence;
	u64 address;
	u64 data_offset;
	u32 count;
	u32 len;
	u32 reason;
	u8 direction;
	bool completion_pending;
};

struct kvm_exec_capsule {
	struct kvm_exec_domain *domain;
	struct file *vcpu_file;
	struct kvm_vcpu *vcpu;
	struct kvm_exec_executor *owner;
	u64 capsule_id;
	u64 lifecycle_generation;
	u64 next_exit_sequence;
	struct kvm_exec_exit_state exit;
	u32 trace_refs;
	bool running;
};

struct kvm_exec_executor {
	struct kref kref;
	struct kvm_exec_domain *domain;
	struct kvm_exec_capsule *current_capsule;
	void *dispatch_region;
	struct list_head node;
	/* Serializes commands submitted through this executor fd. */
	struct mutex run_lock;
	/* Serializes cancellation against the command apply point. */
	spinlock_t dispatch_lock;
	wait_queue_head_t dispatch_wait;
	atomic64_t kick_epoch;
	u64 command_head;
	u64 completion_tail;
	u64 corruption_count;
	u64 last_dispatch_sequence;
	u64 inflight_sequence;
	u64 cancel_sequence;
	u64 last_terminal_sequence;
	u16 last_terminal_status;
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

static struct kvm_exec_dispatch_header *
kvm_exec_dispatch_header(struct kvm_exec_executor *executor)
{
	return executor->dispatch_region;
}

static void kvm_exec_dispatch_init(struct kvm_exec_executor *executor)
{
	struct kvm_exec_dispatch_header *header;

	if (!executor->dispatch_region)
		return;
	header = kvm_exec_dispatch_header(executor);
	header->abi_version = KVM_EXEC_DISPATCH_ABI_VERSION;
	header->region_size = KVM_EXEC_DISPATCH_MMAP_SIZE;
	header->command_offset = KVM_EXEC_DISPATCH_COMMAND_OFFSET;
	header->completion_offset = KVM_EXEC_DISPATCH_COMPLETION_OFFSET;
	header->command_entries = KVM_EXEC_DISPATCH_RING_ENTRIES;
	header->completion_entries = KVM_EXEC_DISPATCH_RING_ENTRIES;
	header->command_entry_size = sizeof(struct kvm_exec_command);
	header->completion_entry_size = sizeof(struct kvm_exec_completion);
}

bool __weak kvm_arch_vcpu_exec_domain_supported(struct kvm_vcpu *vcpu)
{
	return false;
}

bool __weak kvm_arch_vcpu_exec_completion_pending(struct kvm_vcpu *vcpu)
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

u64 kvm_exec_supported_features(void)
{
	return KVM_EXEC_SUPPORTED_FEATURES;
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

	return ioctl == KVM_INTERRUPT ||
	       (READ_ONCE(capsule->domain->paused) &&
		!READ_ONCE(capsule->exit.completion_pending));
}

static bool kvm_exec_has_pending_exit_locked(struct kvm_exec_domain *domain)
{
	struct kvm_exec_capsule *capsule;
	unsigned long index;

	xa_for_each(&domain->capsules, index, capsule) {
		if (capsule->vcpu && capsule->exit.completion_pending)
			return true;
	}
	return false;
}

static bool kvm_exec_control_valid(struct kvm_exec_domain_control *control)
{
	return control->size == sizeof(*control) && !control->flags &&
	       !memchr_inv(control->reserved, 0, sizeof(control->reserved));
}

static void kvm_exec_kick_running_locked(struct kvm_exec_domain *domain)
{
	struct kvm_exec_capsule *capsule;
	struct kvm_exec_executor *executor;
	unsigned long index;

	list_for_each_entry(executor, &domain->executors, node)
		wake_up_interruptible(&executor->dispatch_wait);

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
	} else if (kvm_exec_has_pending_exit_locked(domain)) {
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
		capsule->next_exit_sequence = 0;
		memset(&capsule->exit, 0, sizeof(capsule->exit));
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
	if (capsule->owner || capsule->running || capsule->trace_refs ||
	    capsule->exit.completion_pending) {
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

static void kvm_exec_executor_free(struct kref *kref)
{
	struct kvm_exec_executor *executor =
		container_of(kref, struct kvm_exec_executor, kref);

	if (executor->dispatch_region)
		free_pages_exact(executor->dispatch_region,
				 KVM_EXEC_DISPATCH_MMAP_SIZE);
	kref_put(&executor->domain->kref, kvm_exec_domain_free);
	kfree(executor);
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

	kref_put(&executor->kref, kvm_exec_executor_free);
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
	kref_init(&executor->kref);
	executor->generation =
		kvm_exec_next_generation(&kvm_exec_executor_generation);
	executor->cookie = create.executor_cookie;
	executor->requested_cpu = create.requested_cpu;
	executor->flags = create.flags;
	mutex_init(&executor->run_lock);
	spin_lock_init(&executor->dispatch_lock);
	init_waitqueue_head(&executor->dispatch_wait);
	atomic64_set(&executor->kick_epoch, 0);
	INIT_LIST_HEAD(&executor->node);
	kref_get(&domain->kref);
	if (domain->negotiated_features & KVM_EXEC_FEATURE_DYNAMIC_DISPATCH) {
		executor->dispatch_region =
			alloc_pages_exact(KVM_EXEC_DISPATCH_MMAP_SIZE,
					  GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!executor->dispatch_region) {
			kref_put(&domain->kref, kvm_exec_domain_free);
			kfree(executor);
			put_unused_fd(fd);
			return -ENOMEM;
		}
		kvm_exec_dispatch_init(executor);
	}

	file = anon_inode_getfile("kvm-executor", &kvm_exec_executor_fops,
				  executor, O_RDWR);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		kref_put(&executor->kref, kvm_exec_executor_free);
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
	if (domain->negotiated_features & KVM_EXEC_FEATURE_SYNC_EXITS)
		return -EOPNOTSUPP;
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
	if (domain->negotiated_features & KVM_EXEC_FEATURE_SYNC_EXITS)
		return -EOPNOTSUPP;
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

static struct kvm_exec_command *
kvm_exec_dispatch_commands(struct kvm_exec_executor *executor)
{
	return executor->dispatch_region + KVM_EXEC_DISPATCH_COMMAND_OFFSET;
}

static struct kvm_exec_completion *
kvm_exec_dispatch_completions(struct kvm_exec_executor *executor)
{
	return executor->dispatch_region + KVM_EXEC_DISPATCH_COMPLETION_OFFSET;
}

static bool kvm_exec_dispatch_header_valid(struct kvm_exec_executor *executor)
{
	struct kvm_exec_dispatch_header *header =
		kvm_exec_dispatch_header(executor);

	return READ_ONCE(header->abi_version) == KVM_EXEC_DISPATCH_ABI_VERSION &&
	       READ_ONCE(header->region_size) == KVM_EXEC_DISPATCH_MMAP_SIZE &&
	       READ_ONCE(header->command_offset) ==
			KVM_EXEC_DISPATCH_COMMAND_OFFSET &&
	       READ_ONCE(header->completion_offset) ==
			KVM_EXEC_DISPATCH_COMPLETION_OFFSET &&
	       READ_ONCE(header->command_entries) ==
			KVM_EXEC_DISPATCH_RING_ENTRIES &&
	       READ_ONCE(header->completion_entries) ==
			KVM_EXEC_DISPATCH_RING_ENTRIES &&
	       READ_ONCE(header->command_entry_size) ==
			sizeof(struct kvm_exec_command) &&
	       READ_ONCE(header->completion_entry_size) ==
			sizeof(struct kvm_exec_completion);
}

static int kvm_exec_dispatch_corrupt(struct kvm_exec_executor *executor)
{
	struct kvm_exec_dispatch_header *header =
		kvm_exec_dispatch_header(executor);

	executor->corruption_count++;
	WRITE_ONCE(header->kernel_corruption_count,
		   executor->corruption_count);
	return -EPROTO;
}

static int kvm_exec_dispatch_ring_state(struct kvm_exec_executor *executor,
					bool *has_command,
					bool *completion_full)
{
	struct kvm_exec_dispatch_header *header =
		kvm_exec_dispatch_header(executor);
	u64 command_tail, completion_head;

	if (!kvm_exec_dispatch_header_valid(executor) ||
	    READ_ONCE(header->command_head) != executor->command_head ||
	    READ_ONCE(header->completion_tail) != executor->completion_tail)
		return kvm_exec_dispatch_corrupt(executor);

	/*
	 * The release/acquire pairs are the ownership transfer for each SPSC
	 * entry.  Unsigned subtraction deliberately remains correct if a logical
	 * ring counter wraps; a distance larger than the ring is corruption.
	 */
	/* Pairs with userspace's release publication of a command entry. */
	command_tail = smp_load_acquire(&header->command_tail);
	/* Pairs with userspace's release consumption of a completion entry. */
	completion_head = smp_load_acquire(&header->completion_head);
	if (command_tail - executor->command_head >
			KVM_EXEC_DISPATCH_RING_ENTRIES ||
	    executor->completion_tail - completion_head >
			KVM_EXEC_DISPATCH_RING_ENTRIES)
		return kvm_exec_dispatch_corrupt(executor);

	*has_command = command_tail != executor->command_head;
	*completion_full = executor->completion_tail - completion_head ==
				  KVM_EXEC_DISPATCH_RING_ENTRIES;
	return 0;
}

static bool kvm_exec_dispatch_command_shape_valid(struct kvm_exec_command *cmd)
{
	if (cmd->size != sizeof(*cmd) || cmd->flags ||
	    !cmd->request_sequence || cmd->reserved0 ||
	    memchr_inv(cmd->reserved, 0, sizeof(cmd->reserved)))
		return false;
	if (!!cmd->expected_current_id != !!cmd->expected_current_generation)
		return false;
	if (cmd->opcode == KVM_EXEC_CMD_SWITCH)
		return cmd->target_capsule_id &&
		       cmd->target_lifecycle_generation;
	if (cmd->opcode == KVM_EXEC_CMD_RELEASE)
		return !cmd->target_capsule_id &&
		       !cmd->target_lifecycle_generation;
	return false;
}

static void kvm_exec_snapshot_exit(struct kvm_vcpu *vcpu,
				   struct kvm_exec_exit_state *exit)
{
	struct kvm_run *run = vcpu->run;

	memset(exit, 0, sizeof(*exit));
	exit->reason = run->exit_reason;
	exit->completion_pending =
		kvm_arch_vcpu_exec_completion_pending(vcpu);
	if (run->exit_reason == KVM_EXIT_IO) {
		exit->address = run->io.port;
		exit->data_offset = run->io.data_offset;
		exit->count = run->io.count;
		exit->len = run->io.size;
		exit->direction = run->io.direction;
	} else if (run->exit_reason == KVM_EXIT_MMIO) {
		exit->address = run->mmio.phys_addr;
		exit->len = run->mmio.len;
		exit->direction = run->mmio.is_write;
	}
}

static void kvm_exec_record_exit_locked(struct kvm_exec_capsule *capsule,
					struct kvm_exec_exit_state *exit)
{
	bool completion_pending = exit->completion_pending;

	exit->sequence = ++capsule->next_exit_sequence;
	if (!exit->sequence)
		exit->sequence = ++capsule->next_exit_sequence;
	exit->completion_pending = false;
	capsule->exit = *exit;
	WRITE_ONCE(capsule->exit.completion_pending, completion_pending);
}

static bool kvm_exec_pending_exit_valid(struct kvm_exec_capsule *capsule)
{
	struct kvm_exec_exit_state *exit = &capsule->exit;
	struct kvm_run *run = capsule->vcpu->run;

	if (!exit->completion_pending ||
	    !kvm_arch_vcpu_exec_completion_pending(capsule->vcpu) ||
	    run->exit_reason != exit->reason)
		return false;
	if (exit->reason == KVM_EXIT_IO)
		return run->io.port == exit->address &&
		       run->io.data_offset == exit->data_offset &&
		       run->io.count == exit->count &&
		       run->io.size == exit->len &&
		       run->io.direction == exit->direction;
	if (exit->reason == KVM_EXIT_MMIO)
		return run->mmio.phys_addr == exit->address &&
		       run->mmio.len == exit->len &&
		       run->mmio.is_write == exit->direction;
	return true;
}

static void
kvm_exec_dispatch_finish(struct kvm_exec_executor *executor, u64 sequence,
			 u16 status)
{
	unsigned long flags;

	spin_lock_irqsave(&executor->dispatch_lock, flags);
	if (executor->inflight_sequence == sequence)
		executor->inflight_sequence = 0;
	if (executor->cancel_sequence == sequence)
		executor->cancel_sequence = 0;
	if (sequence >= executor->last_terminal_sequence) {
		executor->last_terminal_sequence = sequence;
		executor->last_terminal_status = status;
	}
	spin_unlock_irqrestore(&executor->dispatch_lock, flags);
}

static bool
kvm_exec_dispatch_begin(struct kvm_exec_executor *executor, u64 sequence,
			u16 *status)
{
	unsigned long flags;
	bool proceed = false;

	spin_lock_irqsave(&executor->dispatch_lock, flags);
	if (sequence <= executor->last_dispatch_sequence) {
		*status = KVM_EXEC_COMPLETE_REJECTED;
	} else {
		executor->last_dispatch_sequence = sequence;
		executor->inflight_sequence = sequence;
		if (executor->cancel_sequence < sequence)
			executor->cancel_sequence = 0;
		if (executor->cancel_sequence == sequence) {
			executor->cancel_sequence = 0;
			*status = KVM_EXEC_COMPLETE_CANCELLED_BEFORE_APPLY;
		} else {
			proceed = true;
		}
	}
	spin_unlock_irqrestore(&executor->dispatch_lock, flags);
	return proceed;
}

static bool kvm_exec_dispatch_cancelled(struct kvm_exec_executor *executor,
					u64 sequence)
{
	return executor->cancel_sequence == sequence;
}

static void kvm_exec_dispatch_owner(struct kvm_exec_executor *executor,
				    struct kvm_exec_completion *completion)
{
	struct kvm_exec_capsule *current_capsule = executor->current_capsule;

	if (!current_capsule)
		return;
	completion->owned_capsule_id = current_capsule->capsule_id;
	completion->owned_lifecycle_generation =
		current_capsule->lifecycle_generation;
}

static void kvm_exec_dispatch_previous(struct kvm_exec_executor *executor,
				       struct kvm_exec_completion *completion)
{
	struct kvm_exec_capsule *current_capsule = executor->current_capsule;

	if (!current_capsule)
		return;
	completion->previous_capsule_id = current_capsule->capsule_id;
	completion->previous_lifecycle_generation =
		current_capsule->lifecycle_generation;
}

static int
kvm_exec_dispatch_consume(struct kvm_exec_executor *executor,
			  struct kvm_exec_completion *completion)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_dispatch_header *header =
		kvm_exec_dispatch_header(executor);
	struct kvm_exec_command command;
	struct kvm_exec_capsule *current_capsule, *target = NULL;
	bool has_command, completion_full;
	unsigned long flags;
	u16 status = KVM_EXEC_COMPLETE_REJECTED;
	int ret;

	ret = kvm_exec_dispatch_ring_state(executor, &has_command,
					   &completion_full);
	if (ret)
		return ret;
	if (!has_command)
		return 0;
	if (completion_full)
		return -ENOSPC;

	memcpy(&command,
	       &kvm_exec_dispatch_commands(executor)
		[executor->command_head % KVM_EXEC_DISPATCH_RING_ENTRIES],
	       sizeof(command));
	executor->command_head++;
	/* Pairs with userspace's acquire load before reusing this slot. */
	smp_store_release(&header->command_head, executor->command_head);
	WRITE_ONCE(header->last_consumed_sequence, command.request_sequence);

	*completion = (struct kvm_exec_completion) {
		.size = sizeof(*completion),
		.request_sequence = command.request_sequence,
		.domain_generation = domain->generation,
		.executor_generation = executor->generation,
		.user_cookie = command.user_cookie,
		.consumed_ns = ktime_get_ns(),
	};

	if (!kvm_exec_dispatch_begin(executor, command.request_sequence,
				     &status))
		goto terminal;
	if (!kvm_exec_dispatch_command_shape_valid(&command) ||
	    command.domain_generation != domain->generation ||
	    command.executor_generation != executor->generation)
		goto terminal;

	mutex_lock(&domain->lock);
	current_capsule = executor->current_capsule;
	kvm_exec_dispatch_previous(executor, completion);
	if ((!current_capsule && command.expected_current_id) ||
	    (current_capsule &&
	     (current_capsule->capsule_id != command.expected_current_id ||
	      current_capsule->lifecycle_generation !=
			command.expected_current_generation))) {
		status = KVM_EXEC_COMPLETE_CURRENT_MISMATCH;
		goto terminal_locked;
	}
	if (current_capsule && current_capsule->exit.completion_pending &&
	    (command.opcode != KVM_EXEC_CMD_SWITCH ||
	     command.target_capsule_id != current_capsule->capsule_id ||
	     command.target_lifecycle_generation !=
		current_capsule->lifecycle_generation)) {
		status = KVM_EXEC_COMPLETE_EXIT_PENDING;
		goto terminal_locked;
	}

	if (command.opcode == KVM_EXEC_CMD_SWITCH) {
		target = xa_load(&domain->capsules, command.target_capsule_id);
		if (!target || !target->vcpu) {
			status = KVM_EXEC_COMPLETE_TARGET_UNKNOWN;
			goto terminal_locked;
		}
		if (target->lifecycle_generation !=
				command.target_lifecycle_generation) {
			status = KVM_EXEC_COMPLETE_TARGET_STALE;
			goto terminal_locked;
		}
		if (target != current_capsule &&
		    target->exit.completion_pending) {
			status = KVM_EXEC_COMPLETE_EXIT_PENDING;
			goto terminal_locked;
		}
		if (current_capsule &&
		    current_capsule->vcpu->kvm != target->vcpu->kvm &&
		    !(domain->negotiated_features &
				KVM_EXEC_FEATURE_CROSS_VM_CHAIN)) {
			status = KVM_EXEC_COMPLETE_CROSS_VM_DISABLED;
			goto terminal_locked;
		}
		if ((target->owner &&
		     (target->owner != executor || target != current_capsule)) ||
		    target->running) {
			status = KVM_EXEC_COMPLETE_TARGET_BUSY;
			goto terminal_locked;
		}
	}

	/* Cancellation and ownership replacement share one serialized apply point. */
	spin_lock_irqsave(&executor->dispatch_lock, flags);
	if (kvm_exec_dispatch_cancelled(executor,
					command.request_sequence)) {
		status = KVM_EXEC_COMPLETE_CANCELLED_BEFORE_APPLY;
	} else if (command.opcode == KVM_EXEC_CMD_RELEASE) {
		if (current_capsule)
			current_capsule->owner = NULL;
		executor->current_capsule = NULL;
		status = KVM_EXEC_COMPLETE_RETURNED;
	} else {
		if (current_capsule != target) {
			if (current_capsule)
				current_capsule->owner = NULL;
			target->owner = executor;
			executor->current_capsule = target;
		}
		status = KVM_EXEC_COMPLETE_APPLIED;
	}
	executor->inflight_sequence = 0;
	if (executor->cancel_sequence == command.request_sequence)
		executor->cancel_sequence = 0;
	executor->last_terminal_sequence = command.request_sequence;
	executor->last_terminal_status = status;
	spin_unlock_irqrestore(&executor->dispatch_lock, flags);
	completion->status = status;
	completion->applied_ns = ktime_get_ns();
	kvm_exec_dispatch_owner(executor, completion);
	mutex_unlock(&domain->lock);
	if (status == KVM_EXEC_COMPLETE_APPLIED ||
	    status == KVM_EXEC_COMPLETE_RETURNED)
		WRITE_ONCE(header->last_applied_sequence,
			   command.request_sequence);
	return 1;

terminal_locked:
	mutex_unlock(&domain->lock);
terminal:
	completion->status = status;
	mutex_lock(&domain->lock);
	if (!completion->previous_capsule_id)
		kvm_exec_dispatch_previous(executor, completion);
	kvm_exec_dispatch_owner(executor, completion);
	mutex_unlock(&domain->lock);
	kvm_exec_dispatch_finish(executor, command.request_sequence, status);
	return 1;
}

static void
kvm_exec_dispatch_publish(struct kvm_exec_executor *executor,
			  struct kvm_exec_completion *completion)
{
	struct kvm_exec_dispatch_header *header =
		kvm_exec_dispatch_header(executor);
	struct kvm_exec_completion *slot =
		&kvm_exec_dispatch_completions(executor)
		 [executor->completion_tail % KVM_EXEC_DISPATCH_RING_ENTRIES];

	memcpy(slot, completion, sizeof(*completion));
	executor->completion_tail++;
	/* Pairs with userspace's acquire load before reading this completion. */
	smp_store_release(&header->completion_tail,
			  executor->completion_tail);
}

static bool kvm_exec_ready(struct kvm_exec_executor *executor, u64 kick_epoch)
{
	struct kvm_exec_dispatch_header *header =
		kvm_exec_dispatch_header(executor);
	u64 command_tail;

	/* Pairs with userspace's release publication of a command entry. */
	command_tail = smp_load_acquire(&header->command_tail);
	return READ_ONCE(executor->domain->paused) ||
	       READ_ONCE(executor->domain->stopping) ||
	       atomic64_read(&executor->kick_epoch) != kick_epoch ||
	       command_tail != executor->command_head;
}

static void kvm_exec_dispatch_run_owner(struct kvm_exec_executor *executor,
					struct kvm_exec_run_dispatch *run)
{
	struct kvm_exec_capsule *capsule = executor->current_capsule;

	if (!capsule)
		return;
	run->owned_capsule_id = capsule->capsule_id;
	run->owned_lifecycle_generation = capsule->lifecycle_generation;
	if (!(executor->domain->negotiated_features &
	      KVM_EXEC_FEATURE_SYNC_EXITS))
		return;
	if (capsule->exit.sequence) {
		run->exit_sequence = capsule->exit.sequence;
		if (capsule->exit.completion_pending)
			run->exit_flags =
				KVM_EXEC_EXIT_F_COMPLETION_PENDING;
	}
}

static long kvm_exec_run_dispatch(struct kvm_exec_executor *executor,
				  void __user *argp)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_dispatch_header *header;
	struct kvm_exec_completion completion;
	struct kvm_exec_capsule *capsule;
	struct kvm_exec_run_dispatch run;
	u64 seen_kick_epoch;
	u32 initial_cpu, final_cpu;
	bool active = false;
	bool completion_pending = false;
	int command_ret, run_ret, ret;

	if (copy_from_user(&run, argp, sizeof(run)))
		return -EFAULT;
	if (run.size != sizeof(run) ||
	    run.flags & ~KVM_EXEC_DISPATCH_F_RETURN_IF_EMPTY ||
	    run.exit_sequence || run.exit_flags || run.reserved0)
		return -EINVAL;
	ret = kvm_exec_domain_access(domain);
	if (ret)
		return ret;
	if (!(domain->negotiated_features & KVM_EXEC_FEATURE_DYNAMIC_DISPATCH))
		return -EOPNOTSUPP;
	if (run.domain_generation != domain->generation ||
	    run.executor_generation != executor->generation)
		return -ESTALE;
	if (mutex_lock_killable(&executor->run_lock))
		return -EINTR;

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
	atomic_inc(&domain->active_runs);
	active = true;
	mutex_unlock(&domain->lock);

	header = kvm_exec_dispatch_header(executor);
	seen_kick_epoch = atomic64_read(&executor->kick_epoch);
	run.return_reason = 0;
	run.run_result = 0;
	run.vcpu_exit_reason = 0;
	run.current_cpu = initial_cpu;
	run.owned_capsule_id = 0;
	run.owned_lifecycle_generation = 0;
	run.exit_sequence = 0;
	run.exit_flags = 0;
	run.reserved0 = 0;

	for (;;) {
		u64 kick_epoch = atomic64_read(&executor->kick_epoch);
		struct kvm_exec_exit_state observed_exit;
		bool attempted_kvm_run = false;
		bool entry_allowed;
		bool invalid_completion = false;
		bool pending_after_run = false;
		bool kick_pending;
		u32 reported_exit_reason;

		mutex_lock(&domain->lock);
		if (domain->stopping || domain->paused) {
			if (completion_pending) {
				kvm_exec_dispatch_publish(executor, &completion);
				completion_pending = false;
			}
			run.return_reason = domain->stopping ?
				KVM_EXEC_RETURN_DOMAIN_STOPPING :
				KVM_EXEC_RETURN_DOMAIN_PAUSED;
			run.run_result = -EINTR;
			mutex_unlock(&domain->lock);
			break;
		}
		mutex_unlock(&domain->lock);

		if (kick_epoch != seen_kick_epoch) {
			mutex_lock(&domain->lock);
			capsule = executor->current_capsule;
			if (capsule && !capsule->running)
				kvm_clear_request(KVM_REQ_EXEC_DOMAIN_EXIT,
						  capsule->vcpu);
			mutex_unlock(&domain->lock);
			seen_kick_epoch = kick_epoch;
		}

		command_ret = 0;
		if (!completion_pending) {
			memset(&completion, 0, sizeof(completion));
			command_ret = kvm_exec_dispatch_consume(executor, &completion);
			if (command_ret == -EPROTO) {
				run.return_reason =
					KVM_EXEC_RETURN_DISPATCH_CORRUPT;
				run.run_result = -EPROTO;
				break;
			}
			if (command_ret == -ENOSPC) {
				run.return_reason =
					KVM_EXEC_RETURN_COMPLETION_FULL;
				run.run_result = -ENOSPC;
				break;
			}
			if (command_ret > 0) {
				if (completion.status == KVM_EXEC_COMPLETE_APPLIED &&
				    completion.owned_capsule_id)
					completion_pending = true;
				else
					kvm_exec_dispatch_publish(executor,
								  &completion);
			}
		}
		mutex_lock(&domain->lock);
		if (domain->stopping) {
			if (completion_pending) {
				kvm_exec_dispatch_publish(executor, &completion);
				completion_pending = false;
			}
			run.return_reason = KVM_EXEC_RETURN_DOMAIN_STOPPING;
			run.run_result = -EINTR;
			mutex_unlock(&domain->lock);
			break;
		}
		if (domain->paused) {
			if (completion_pending) {
				kvm_exec_dispatch_publish(executor, &completion);
				completion_pending = false;
			}
			run.return_reason = KVM_EXEC_RETURN_DOMAIN_PAUSED;
			run.run_result = -EINTR;
			mutex_unlock(&domain->lock);
			break;
		}
		capsule = executor->current_capsule;
		if (!capsule) {
			mutex_unlock(&domain->lock);
			/*
			 * Recheck the ring after publishing a terminal command.
			 * This lets RETURN_IF_EMPTY observe the now-empty ring and
			 * lets a queued batch advance without requiring one kick per
			 * rejected command.
			 */
			if (command_ret > 0)
				continue;
			if (run.flags & KVM_EXEC_DISPATCH_F_RETURN_IF_EMPTY) {
				run.return_reason =
					KVM_EXEC_RETURN_DISPATCH_EMPTY;
				break;
			}
			ret = wait_event_interruptible(executor->dispatch_wait,
						       kvm_exec_ready(executor,
								      seen_kick_epoch));
			if (ret) {
				run.return_reason = KVM_EXEC_RETURN_SIGNAL;
				run.run_result = -EINTR;
				break;
			}
			continue;
		}
		capsule->running = true;
		mutex_unlock(&domain->lock);

		if (mutex_lock_killable(&capsule->vcpu->mutex)) {
			if (completion_pending) {
				kvm_exec_dispatch_publish(executor, &completion);
				completion_pending = false;
			}
			mutex_lock(&domain->lock);
			capsule->running = false;
			mutex_unlock(&domain->lock);
			run.return_reason = KVM_EXEC_RETURN_SIGNAL;
			run.run_result = -EINTR;
			break;
		}
		kick_pending = atomic64_read(&executor->kick_epoch) !=
			       seen_kick_epoch;
		entry_allowed = !READ_ONCE(domain->stopping) &&
				!READ_ONCE(domain->paused) &&
				!kick_pending &&
				capsule->vcpu->exec_capsule == capsule &&
				kvm_arch_vcpu_exec_domain_supported(capsule->vcpu);
		if (entry_allowed && capsule->exit.completion_pending &&
		    !kvm_exec_pending_exit_valid(capsule)) {
			entry_allowed = false;
			invalid_completion = true;
		}
		if (completion_pending && !kick_pending) {
			if (entry_allowed) {
				completion.entry_attempt_ns = ktime_get_ns();
				WRITE_ONCE(header->last_entry_sequence,
					   completion.request_sequence);
				WRITE_ONCE(header->last_entry_ns,
					   completion.entry_attempt_ns);
			}
			kvm_exec_dispatch_publish(executor, &completion);
			completion_pending = false;
		}
		reported_exit_reason = capsule->vcpu->run->exit_reason;
		if (invalid_completion) {
			run_ret = -EINVAL;
			capsule->vcpu->run->exit_reason = capsule->exit.reason;
			reported_exit_reason = capsule->exit.reason;
		} else if (!entry_allowed) {
			run_ret = -EINTR;
			/*
			 * A kick may arrive after userspace supplied a synchronous
			 * response but before KVM has applied it.  The kvm_run page is
			 * still the capsule's authoritative completion state, so an
			 * interrupted entry attempt must not replace its exit metadata.
			 */
			reported_exit_reason = KVM_EXIT_INTR;
		} else {
			attempted_kvm_run = true;
			run_ret = kvm_vcpu_run(capsule->vcpu);
			reported_exit_reason = capsule->vcpu->run->exit_reason;
			pending_after_run =
				kvm_arch_vcpu_exec_completion_pending(capsule->vcpu);
			if (!run_ret)
				kvm_exec_snapshot_exit(capsule->vcpu,
						       &observed_exit);
		}
		final_cpu = get_cpu();
		put_cpu();
		run.run_result = run_ret;
		run.vcpu_exit_reason = reported_exit_reason;
		run.current_cpu = final_cpu;
		mutex_unlock(&capsule->vcpu->mutex);

		mutex_lock(&domain->lock);
		capsule->running = false;
		if (invalid_completion) {
			run.return_reason =
				KVM_EXEC_RETURN_INVALID_COMPLETION;
			mutex_unlock(&domain->lock);
			break;
		}
		if (!run_ret) {
			kvm_exec_record_exit_locked(capsule, &observed_exit);
		} else if (attempted_kvm_run &&
			   capsule->exit.completion_pending &&
			   !pending_after_run) {
			WRITE_ONCE(capsule->exit.completion_pending, false);
		}
		if (domain->stopping) {
			run.return_reason = KVM_EXEC_RETURN_DOMAIN_STOPPING;
			mutex_unlock(&domain->lock);
			break;
		}
		if (domain->paused) {
			run.return_reason = KVM_EXEC_RETURN_DOMAIN_PAUSED;
			mutex_unlock(&domain->lock);
			break;
		}
		mutex_unlock(&domain->lock);

		if ((executor->flags & KVM_EXECUTOR_F_STRICT_CPU) &&
		    final_cpu != executor->requested_cpu) {
			run.return_reason = KVM_EXEC_RETURN_CPU_MIGRATED;
			break;
		}
		if (run_ret == -EINTR) {
			if (atomic64_read(&executor->kick_epoch) !=
					seen_kick_epoch)
				continue;
			run.return_reason = KVM_EXEC_RETURN_SIGNAL;
			break;
		}
		if (run_ret || run.vcpu_exit_reason != KVM_EXIT_DEBUG) {
			run.return_reason = KVM_EXEC_RETURN_VCPU_EXIT;
			break;
		}
	}

	mutex_lock(&domain->lock);
	kvm_exec_dispatch_run_owner(executor, &run);
	if (active)
		atomic_dec(&domain->active_runs);
	mutex_unlock(&domain->lock);
	wake_up_all(&domain->drain_wait);
	run.command_head = executor->command_head;
	run.completion_tail = executor->completion_tail;
	run.corruption_count = executor->corruption_count;
	run.reserved0 = 0;
	ret = copy_to_user(argp, &run, sizeof(run)) ? -EFAULT : 0;
	goto out_executor;

out_domain:
	mutex_unlock(&domain->lock);
out_executor:
	mutex_unlock(&executor->run_lock);
	return ret;
}

static long kvm_exec_kick(struct kvm_exec_executor *executor,
			  void __user *argp)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_dispatch_header *header;
	struct kvm_exec_capsule *capsule;
	struct kvm_exec_kick kick;
	u64 epoch;
	int ret;

	if (copy_from_user(&kick, argp, sizeof(kick)))
		return -EFAULT;
	if (kick.size != sizeof(kick) || kick.flags ||
	    !kick.request_sequence ||
	    memchr_inv(kick.reserved, 0, sizeof(kick.reserved)))
		return -EINVAL;
	ret = kvm_exec_domain_access(domain);
	if (ret)
		return ret;
	if (!(domain->negotiated_features & KVM_EXEC_FEATURE_DYNAMIC_DISPATCH))
		return -EOPNOTSUPP;
	if (kick.domain_generation != domain->generation ||
	    kick.executor_generation != executor->generation)
		return -ESTALE;

	/* Pair the userspace command publication with the runner's acquire load. */
	smp_mb();
	mutex_lock(&domain->lock);
	if (domain->stopping) {
		mutex_unlock(&domain->lock);
		return -ESHUTDOWN;
	}
	epoch = atomic64_inc_return(&executor->kick_epoch);
	header = kvm_exec_dispatch_header(executor);
	WRITE_ONCE(header->kernel_kick_count, epoch);
	WRITE_ONCE(header->last_kick_sequence, kick.request_sequence);
	WRITE_ONCE(header->last_kick_ns, ktime_get_ns());

	capsule = executor->current_capsule;
	if (capsule && capsule->running) {
		kvm_make_request(KVM_REQ_EXEC_DOMAIN_EXIT, capsule->vcpu);
		kvm_make_request(KVM_REQ_UNBLOCK, capsule->vcpu);
		kvm_vcpu_kick(capsule->vcpu);
	}
	mutex_unlock(&domain->lock);
	wake_up_interruptible(&executor->dispatch_wait);
	return 0;
}

static long kvm_exec_cancel(struct kvm_exec_executor *executor,
			    void __user *argp)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_cancel cancel;
	unsigned long flags;
	int ret;

	if (copy_from_user(&cancel, argp, sizeof(cancel)))
		return -EFAULT;
	if (cancel.size != sizeof(cancel) || cancel.flags ||
	    !cancel.request_sequence || cancel.reserved0 ||
	    memchr_inv(cancel.reserved, 0, sizeof(cancel.reserved)))
		return -EINVAL;
	ret = kvm_exec_domain_access(domain);
	if (ret)
		return ret;
	if (!(domain->negotiated_features & KVM_EXEC_FEATURE_DYNAMIC_DISPATCH))
		return -EOPNOTSUPP;
	if (cancel.domain_generation != domain->generation ||
	    cancel.executor_generation != executor->generation)
		return -ESTALE;
	if (READ_ONCE(domain->stopping))
		return -ESHUTDOWN;

	spin_lock_irqsave(&executor->dispatch_lock, flags);
	if (cancel.request_sequence <= executor->last_terminal_sequence) {
		if (cancel.request_sequence == executor->last_terminal_sequence &&
		    executor->last_terminal_status ==
				KVM_EXEC_COMPLETE_CANCELLED_BEFORE_APPLY)
			cancel.status = KVM_EXEC_CANCEL_ALREADY_CANCELLED;
		else if (cancel.request_sequence ==
				 executor->last_terminal_sequence &&
			 (executor->last_terminal_status ==
					KVM_EXEC_COMPLETE_APPLIED ||
			  executor->last_terminal_status ==
					KVM_EXEC_COMPLETE_RETURNED))
			cancel.status = KVM_EXEC_CANCEL_APPLIED;
		else
			cancel.status = KVM_EXEC_CANCEL_STALE;
	} else if (executor->cancel_sequence &&
		   executor->cancel_sequence != cancel.request_sequence) {
		ret = -EBUSY;
		goto out_unlock;
	} else {
		executor->cancel_sequence = cancel.request_sequence;
		cancel.status = KVM_EXEC_CANCEL_ACCEPTED;
	}
	ret = 0;
out_unlock:
	spin_unlock_irqrestore(&executor->dispatch_lock, flags);
	if (ret)
		return ret;
	memset(cancel.reserved, 0, sizeof(cancel.reserved));
	return copy_to_user(argp, &cancel, sizeof(cancel)) ? -EFAULT : 0;
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
	if (ioctl == KVM_EXEC_RUN_DISPATCH)
		return kvm_exec_run_dispatch(executor, (void __user *)arg);
	if (ioctl == KVM_EXEC_KICK)
		return kvm_exec_kick(executor, (void __user *)arg);
	if (ioctl == KVM_EXEC_CANCEL)
		return kvm_exec_cancel(executor, (void __user *)arg);
	return -ENOTTY;
}

static void kvm_exec_executor_vma_open(struct vm_area_struct *vma)
{
	struct kvm_exec_executor *executor = vma->vm_private_data;

	kref_get(&executor->kref);
}

static void kvm_exec_executor_vma_close(struct vm_area_struct *vma)
{
	struct kvm_exec_executor *executor = vma->vm_private_data;

	kref_put(&executor->kref, kvm_exec_executor_free);
}

static const struct vm_operations_struct kvm_exec_executor_vm_ops = {
	.open = kvm_exec_executor_vma_open,
	.close = kvm_exec_executor_vma_close,
};

static int kvm_exec_executor_mmap(struct file *file,
				  struct vm_area_struct *vma)
{
	struct kvm_exec_executor *executor = file->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn;
	int ret;

	ret = kvm_exec_domain_access(executor->domain);
	if (ret)
		return ret;
	if (!executor->dispatch_region)
		return -EOPNOTSUPP;
	if (vma->vm_pgoff || size != KVM_EXEC_DISPATCH_MMAP_SIZE ||
	    !(vma->vm_flags & VM_SHARED) || (vma->vm_flags & VM_EXEC))
		return -EINVAL;

	pfn = page_to_pfn(virt_to_page(executor->dispatch_region));
	vm_flags_set(vma, VM_DONTCOPY | VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_ops = &kvm_exec_executor_vm_ops;
	vma->vm_private_data = executor;
	kvm_exec_executor_vma_open(vma);
	ret = remap_pfn_range(vma, vma->vm_start, pfn, size,
			      vma->vm_page_prot);
	if (ret)
		kvm_exec_executor_vma_close(vma);
	return ret;
}

static const struct file_operations kvm_exec_executor_fops = {
	.owner = THIS_MODULE,
	.release = kvm_exec_executor_release,
	.unlocked_ioctl = kvm_exec_executor_ioctl,
	.mmap = kvm_exec_executor_mmap,
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
	    ((create.requested_features & KVM_EXEC_FEATURE_SYNC_EXITS) &&
	     !(create.requested_features & KVM_EXEC_FEATURE_DYNAMIC_DISPATCH)) ||
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
