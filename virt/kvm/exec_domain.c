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

#include <trace/events/kvm.h>

#define KVM_EXEC_SUPPORTED_FEATURES \
	(KVM_EXEC_FEATURE_BASE_OBJECTS | KVM_EXEC_FEATURE_INTRA_VM_CHAIN | \
	 KVM_EXEC_FEATURE_CROSS_VM_CHAIN | KVM_EXEC_FEATURE_DYNAMIC_DISPATCH | \
	 KVM_EXEC_FEATURE_SYNC_EXITS | KVM_EXEC_FEATURE_ASYNC_PIO_WRITE | \
	 KVM_EXEC_FEATURE_RETURN_KICK | KVM_EXEC_FEATURE_LIFECYCLE_STATE | \
	 KVM_EXEC_FEATURE_EXACT_INTERRUPT | \
	 KVM_EXEC_FEATURE_INTERRUPT_PUBLICATION | \
	 KVM_EXEC_FEATURE_LOCAL_APIC_DELIVERY | \
	 KVM_EXEC_FEATURE_NOTIFICATION_RING)

struct kvm_exec_domain;
struct kvm_exec_executor;
struct kvm_exec_notification_runner;

struct kvm_exec_pending_interrupt {
	u64 sequence;
	u64 capsule_id;
	u64 lifecycle_generation;
	u32 vector;
	u32 flags;
	u32 delivery;
};

struct kvm_exec_interrupt_request {
	u64 domain_generation;
	u64 executor_generation;
	u64 request_sequence;
	u64 capsule_id;
	u64 lifecycle_generation;
	u64 correlation_cookie;
	u32 vector;
	u32 flags;
	u32 requested_delivery;
};

static bool kvm_exec_delivery_uses_local_apic(u32 delivery)
{
	return delivery == KVM_EXEC_INTERRUPT_DELIVERY_LOCAL_APIC_KICK ||
	       delivery == KVM_EXEC_INTERRUPT_DELIVERY_POSTED;
}

struct kvm_exec_exit_state {
	u64 sequence;
	u64 address;
	u64 data_offset;
	u32 count;
	u32 len;
	u32 reason;
	u8 direction;
	u8 data[8];
	bool payload_valid;
	bool completion_pending;
	bool async_request_pending;
	bool async_completion_ready;
	bool async_entry_authorized;
	bool async_reentry_required;
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
	atomic_t block_reason;
	atomic_t last_cpu;
	atomic64_t run_count;
	atomic64_t exit_count;
	atomic64_t halt_count;
	atomic64_t wake_count;
	atomic64_t runtime_ns;
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
	/* Protects the exact interrupt request independently of domain->lock. */
	spinlock_t interrupt_lock;
	wait_queue_head_t dispatch_wait;
	atomic64_t kick_epoch;
	atomic64_t return_kick_epoch;
	u64 consumed_return_kick_epoch;
	u64 mapped_boundary_return_kick_epoch;
	u64 command_head;
	u64 completion_tail;
	u64 exit_request_tail;
	u64 exit_completion_head;
	u64 return_count;
	u64 corruption_count;
	atomic_t last_cpu;
	atomic64_t run_count;
	atomic64_t switch_count;
	atomic64_t release_count;
	atomic64_t rejected_count;
	atomic64_t cancelled_count;
	atomic64_t exit_count;
	atomic64_t failure_count;
	atomic64_t runtime_ns;
	u64 last_dispatch_sequence;
	u64 inflight_sequence;
	u64 cancel_sequence;
	u64 last_terminal_sequence;
	u16 last_terminal_status;
	u64 pending_interrupt_sequence;
	u64 pending_interrupt_capsule_id;
	u64 pending_interrupt_lifecycle_generation;
	u64 last_interrupt_sequence;
	u64 interrupt_queued_count;
	u64 interrupt_applied_count;
	u64 interrupt_delivery_count;
	u64 interrupt_vector_queued_count;
	u64 interrupt_forced_kick_count;
	u64 interrupt_handler_delivery_count;
	u64 interrupt_eoi_count;
	u64 interrupt_coalesced_count;
	u64 interrupt_rejection_count;
	u64 interrupt_posted_count;
	u64 interrupt_posted_coalesced_count;
	u64 interrupt_posted_root_rejection_count;
	u64 interrupt_posted_inactive_rejection_count;
	u64 interrupt_posted_stale_rejection_count;
	u64 interrupt_posted_disarmed_count;
	u64 interrupt_posted_superseded_count;
	u64 interrupt_posted_target_exit_count;
	u64 interrupt_posted_target_exit_baseline;
	u64 last_interrupt_accepted_ns;
	u64 last_interrupt_delivered_ns;
	u64 last_interrupt_accepted_tsc;
	u64 last_interrupt_delivered_tsc;
	u32 last_interrupt_delivery;
	u32 pending_interrupt_vector;
	u32 pending_interrupt_flags;
	u32 pending_interrupt_delivery;
	bool pending_interrupt_arch_queued;
	u64 retained_halt_capsule_id;
	u64 retained_halt_lifecycle_generation;
	u64 generation;
	u64 cookie;
	u64 last_request_sequence;
	u32 requested_cpu;
	u32 last_interrupt_notification_cpu;
	u32 flags;
	bool pending_interrupt_handler_observed;
	bool listed;
};

struct kvm_exec_notification_runner {
	struct kref kref;
	struct kvm_exec_domain *domain;
	void *region;
	/* Serializes entry to the long-running runner ioctl. */
	struct mutex run_lock;
	/* Protects runner lifecycle flags and state. */
	spinlock_t state_lock;
	wait_queue_head_t wait;
	u64 generation;
	u64 cookie;
	atomic64_t heartbeat;
	atomic64_t consumed_count;
	atomic64_t completed_count;
	atomic64_t full_count;
	atomic64_t malformed_count;
	atomic64_t stale_count;
	atomic64_t high_watermark;
	atomic64_t return_count;
	u64 runner_tid;
	u32 requested_cpu;
	atomic_t observed_cpu;
	u32 state;
	int last_error;
	bool listed;
	bool running;
	bool drain_requested;
	bool stop_requested;
	bool full_observed;
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
	u32 interrupt_delivery;
	u32 max_capsules;
	u32 max_executors;
	u32 nr_capsule_slots;
	u32 nr_attached;
	u32 nr_executors;
	struct kvm_exec_notification_runner *notification_runner;
	bool interrupt_delivery_configured;
	bool paused;
	bool stopping;
};

static atomic64_t kvm_exec_domain_generation = ATOMIC64_INIT(0);
static atomic64_t kvm_exec_executor_generation = ATOMIC64_INIT(0);
static atomic64_t kvm_exec_notification_generation = ATOMIC64_INIT(0);

static const struct file_operations kvm_exec_domain_fops;
static const struct file_operations kvm_exec_executor_fops;
static const struct file_operations kvm_exec_notification_fops;

static void kvm_exec_interrupt_clear_retained_halt(
	struct kvm_exec_executor *executor);
static void kvm_exec_interrupt_abort(struct kvm_exec_executor *executor,
				     bool superseded);
static bool
kvm_exec_interrupt_snapshot(struct kvm_exec_executor *executor,
			    struct kvm_exec_pending_interrupt *interrupt);

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
	header->exit_request_offset = KVM_EXEC_EXIT_REQUEST_OFFSET;
	header->exit_completion_offset = KVM_EXEC_EXIT_COMPLETION_OFFSET;
	header->exit_request_entries = KVM_EXEC_DISPATCH_RING_ENTRIES;
	header->exit_completion_entries = KVM_EXEC_DISPATCH_RING_ENTRIES;
	header->exit_request_entry_size = sizeof(struct kvm_exec_exit_request);
	header->exit_completion_entry_size =
		sizeof(struct kvm_exec_exit_completion);
}

bool __weak kvm_arch_vcpu_exec_domain_supported(struct kvm_vcpu *vcpu)
{
	return false;
}

u64 __weak kvm_arch_exec_host_tsc(void)
{
	return 0;
}

bool __weak kvm_arch_vcpu_exec_completion_pending(struct kvm_vcpu *vcpu)
{
	return false;
}

bool __weak kvm_arch_vcpu_exec_copy_pio_data(struct kvm_vcpu *vcpu,
					     void *data, size_t len)
{
	return false;
}

u64 __weak kvm_arch_exec_supported_features(void)
{
	return 0;
}

int __weak kvm_arch_vcpu_exec_inject_interrupt(struct kvm_vcpu *vcpu,
					       u32 vector)
{
	return -EOPNOTSUPP;
}

bool __weak kvm_arch_vcpu_exec_direct_pending(struct kvm_vcpu *vcpu,
					      u32 vector)
{
	return false;
}

void __weak kvm_arch_vcpu_exec_cancel_direct(struct kvm_vcpu *vcpu, u32 vector)
{
}

int __weak
kvm_arch_vcpu_exec_configure_interrupt_delivery(struct kvm_vcpu *vcpu,
						 u32 delivery, bool enable)
{
	return -EOPNOTSUPP;
}

int __weak
kvm_arch_vcpu_exec_queue_local_apic_interrupt(struct kvm_vcpu *vcpu,
					       u32 vector, bool *coalesced)
{
	return -EOPNOTSUPP;
}

void __weak
kvm_arch_vcpu_exec_cancel_local_apic_interrupt(struct kvm_vcpu *vcpu,
					       u32 vector)
{
}

int __weak
kvm_arch_vcpu_exec_queue_posted_interrupt(struct kvm_vcpu *vcpu,
					    u32 vector, bool *coalesced)
{
	return -EOPNOTSUPP;
}

bool __weak
kvm_arch_vcpu_exec_posted_interrupt_active(struct kvm_vcpu *vcpu)
{
	return false;
}

u64 __weak kvm_arch_exec_posted_notification_exits(u32 cpu)
{
	return 0;
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
	return KVM_EXEC_SUPPORTED_FEATURES |
	       kvm_arch_exec_supported_features();
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

	if (!capsule)
		return false;
	/* kvm_vcpu_ioctl() already serializes KVM_INTERRUPT with vCPU entry. */
	if (ioctl == KVM_INTERRUPT)
		return true;
	if (READ_ONCE(capsule->running))
		return false;

	return READ_ONCE(capsule->domain->paused) &&
	       !READ_ONCE(capsule->exit.completion_pending);
}

void kvm_exec_domain_vcpu_ioctl_complete(struct kvm_vcpu *vcpu,
					 unsigned int ioctl, long result)
{
	struct kvm_exec_capsule *capsule = vcpu->exec_capsule;

	if (!capsule || ioctl != KVM_INTERRUPT || result)
		return;
	if (!(capsule->domain->negotiated_features &
	      KVM_EXEC_FEATURE_LIFECYCLE_STATE))
		return;
	if (atomic_cmpxchg(&capsule->block_reason, KVM_EXEC_BLOCK_HLT,
			   KVM_EXEC_BLOCK_NONE) == KVM_EXEC_BLOCK_HLT)
		atomic64_inc(&capsule->wake_count);
}

static int kvm_exec_vcpu_run(struct kvm_exec_executor *executor,
			     struct kvm_exec_capsule *capsule)
{
	u64 start_ns = ktime_get_ns();
	u64 runtime_ns;
	u32 cpu;
	int ret;

	ret = kvm_vcpu_run(capsule->vcpu);
	runtime_ns = ktime_get_ns() - start_ns;
	cpu = get_cpu();
	put_cpu();
	atomic_set(&capsule->last_cpu, cpu);
	atomic64_inc(&capsule->run_count);
	atomic64_add(runtime_ns, &capsule->runtime_ns);
	atomic_set(&executor->last_cpu, cpu);
	atomic64_inc(&executor->run_count);
	atomic64_add(runtime_ns, &executor->runtime_ns);
	return ret;
}

static void kvm_exec_account_exit(struct kvm_exec_executor *executor,
				  struct kvm_exec_capsule *capsule,
				  u32 exit_reason)
{
	if (!(capsule->domain->negotiated_features &
	      KVM_EXEC_FEATURE_LIFECYCLE_STATE))
		return;
	atomic64_inc(&capsule->exit_count);
	atomic64_inc(&executor->exit_count);
	if (exit_reason == KVM_EXIT_HLT) {
		atomic_set(&capsule->block_reason, KVM_EXEC_BLOCK_HLT);
		atomic64_inc(&capsule->halt_count);
	} else {
		atomic_set(&capsule->block_reason, KVM_EXEC_BLOCK_VMM_EXIT);
	}
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

	list_for_each_entry(executor, &domain->executors, node) {
		kvm_exec_interrupt_abort(executor, false);
		executor->current_capsule = NULL;
	}
	xa_for_each(&domain->capsules, index, capsule) {
		if (!capsule->running) {
			capsule->owner = NULL;
			atomic_cmpxchg(&capsule->block_reason,
				       KVM_EXEC_BLOCK_VMM_EXIT,
				       KVM_EXEC_BLOCK_NONE);
		}
	}
}

static bool
kvm_exec_has_pending_apic_interrupt_locked(struct kvm_exec_domain *domain)
{
	struct kvm_exec_executor *executor;
	struct kvm_exec_pending_interrupt interrupt;

	lockdep_assert_held(&domain->lock);
	list_for_each_entry(executor, &domain->executors, node) {
		if (kvm_exec_interrupt_snapshot(executor, &interrupt) &&
		    kvm_exec_delivery_uses_local_apic(interrupt.delivery))
			return true;
	}
	return false;
}

static int kvm_exec_domain_pause(struct kvm_exec_domain *domain)
{
	int ret = 0;

	mutex_lock(&domain->lock);
	if (domain->stopping) {
		ret = -ESHUTDOWN;
	} else if (kvm_exec_has_pending_apic_interrupt_locked(domain)) {
		ret = -EBUSY;
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
		if (kvm_exec_delivery_uses_local_apic(
			    domain->interrupt_delivery)) {
			ret = kvm_arch_vcpu_exec_configure_interrupt_delivery(
				vcpu, domain->interrupt_delivery, true);
			if (ret)
				goto out_vcpu;
		}
		capsule->vcpu_file = vcpu_file;
		capsule->vcpu = vcpu;
		capsule->lifecycle_generation = attach.lifecycle_generation;
		capsule->next_exit_sequence = 0;
		memset(&capsule->exit, 0, sizeof(capsule->exit));
		atomic_set(&capsule->block_reason, KVM_EXEC_BLOCK_NONE);
		atomic_set(&capsule->last_cpu, KVM_EXEC_CPU_ANY);
		atomic64_set(&capsule->run_count, 0);
		atomic64_set(&capsule->exit_count, 0);
		atomic64_set(&capsule->halt_count, 0);
		atomic64_set(&capsule->wake_count, 0);
		atomic64_set(&capsule->runtime_ns, 0);
		vcpu->exec_capsule = capsule;
		domain->nr_attached++;
		ret = 0;
	}
out_vcpu:
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
	if (kvm_exec_delivery_uses_local_apic(domain->interrupt_delivery)) {
		ret = kvm_arch_vcpu_exec_configure_interrupt_delivery(
			capsule->vcpu, domain->interrupt_delivery, false);
		if (ret) {
			mutex_unlock(&capsule->vcpu->mutex);
			goto out;
		}
	}
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

static long kvm_exec_query_capsule(struct kvm_exec_domain *domain,
				   void __user *argp)
{
	struct kvm_exec_query_capsule query;
	struct kvm_exec_capsule *capsule;
	u32 block_reason;
	int ret = 0;

	if (!(domain->negotiated_features & KVM_EXEC_FEATURE_LIFECYCLE_STATE))
		return -EOPNOTSUPP;
	if (copy_from_user(&query, argp, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.flags || !query.capsule_id ||
	    !query.lifecycle_generation || query.capsule_id > ULONG_MAX ||
	    memchr_inv(query.reserved, 0, sizeof(query.reserved)))
		return -EINVAL;
	if (query.domain_generation != domain->generation)
		return -ESTALE;

	mutex_lock(&domain->lock);
	capsule = xa_load(&domain->capsules, query.capsule_id);
	if (!capsule || !capsule->vcpu) {
		ret = -ENOENT;
		goto out;
	}
	if (capsule->lifecycle_generation != query.lifecycle_generation) {
		ret = -ESTALE;
		goto out;
	}

	block_reason = atomic_read(&capsule->block_reason);
	query.state = KVM_EXEC_CAPSULE_STATE_READY;
	if (domain->stopping)
		query.state = KVM_EXEC_CAPSULE_STATE_STOPPING;
	else if (capsule->exit.completion_pending)
		query.state = KVM_EXEC_CAPSULE_STATE_COMPLETION_PENDING;
	else if (capsule->running)
		query.state = KVM_EXEC_CAPSULE_STATE_RUNNING;
	else if (block_reason == KVM_EXEC_BLOCK_HLT)
		query.state = KVM_EXEC_CAPSULE_STATE_BLOCKED_HLT;
	else if (block_reason == KVM_EXEC_BLOCK_VMM_EXIT)
		query.state = KVM_EXEC_CAPSULE_STATE_BLOCKED_VMM;
	query.block_reason = block_reason;
	query.owner_executor_generation = capsule->owner ?
		capsule->owner->generation : 0;
	query.owner_cookie = capsule->owner ? capsule->owner->cookie : 0;
	query.exit_sequence = capsule->exit.sequence;
	query.run_count = atomic64_read(&capsule->run_count);
	query.exit_count = atomic64_read(&capsule->exit_count);
	query.halt_count = atomic64_read(&capsule->halt_count);
	query.wake_count = atomic64_read(&capsule->wake_count);
	query.runtime_ns = atomic64_read(&capsule->runtime_ns);
	query.last_cpu = atomic_read(&capsule->last_cpu);
	query.reserved0 = 0;
	memset(query.reserved, 0, sizeof(query.reserved));
out:
	mutex_unlock(&domain->lock);
	if (ret)
		return ret;
	return copy_to_user(argp, &query, sizeof(query)) ? -EFAULT : 0;
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
		struct kvm_exec_pending_interrupt interrupt;

		if (kvm_exec_interrupt_snapshot(executor, &interrupt) &&
		    interrupt.delivery == KVM_EXEC_INTERRUPT_DELIVERY_POSTED)
			domain->stopping = true;
		kvm_exec_interrupt_abort(executor, false);
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
	executor->last_interrupt_notification_cpu = KVM_EXEC_CPU_ANY;
	executor->flags = create.flags;
	mutex_init(&executor->run_lock);
	spin_lock_init(&executor->dispatch_lock);
	spin_lock_init(&executor->interrupt_lock);
	init_waitqueue_head(&executor->dispatch_wait);
	atomic64_set(&executor->kick_epoch, 0);
	atomic64_set(&executor->return_kick_epoch, 0);
	atomic_set(&executor->last_cpu, KVM_EXEC_CPU_ANY);
	atomic64_set(&executor->run_count, 0);
	atomic64_set(&executor->switch_count, 0);
	atomic64_set(&executor->release_count, 0);
	atomic64_set(&executor->rejected_count, 0);
	atomic64_set(&executor->cancelled_count, 0);
	atomic64_set(&executor->exit_count, 0);
	atomic64_set(&executor->failure_count, 0);
	atomic64_set(&executor->runtime_ns, 0);
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

static struct kvm_exec_exit_request *
kvm_exec_exit_requests(struct kvm_exec_executor *executor)
{
	return executor->dispatch_region + KVM_EXEC_EXIT_REQUEST_OFFSET;
}

static struct kvm_exec_exit_completion *
kvm_exec_exit_completions(struct kvm_exec_executor *executor)
{
	return executor->dispatch_region + KVM_EXEC_EXIT_COMPLETION_OFFSET;
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
			sizeof(struct kvm_exec_completion) &&
	       READ_ONCE(header->exit_request_offset) ==
			KVM_EXEC_EXIT_REQUEST_OFFSET &&
	       READ_ONCE(header->exit_completion_offset) ==
			KVM_EXEC_EXIT_COMPLETION_OFFSET &&
	       READ_ONCE(header->exit_request_entries) ==
			KVM_EXEC_DISPATCH_RING_ENTRIES &&
	       READ_ONCE(header->exit_completion_entries) ==
			KVM_EXEC_DISPATCH_RING_ENTRIES &&
	       READ_ONCE(header->exit_request_entry_size) ==
			sizeof(struct kvm_exec_exit_request) &&
	       READ_ONCE(header->exit_completion_entry_size) ==
			sizeof(struct kvm_exec_exit_completion) &&
	       !READ_ONCE(header->reserved0[0]) &&
	       !READ_ONCE(header->reserved0[1]);
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
		u64 bytes = (u64)run->io.count * run->io.size;

		exit->address = run->io.port;
		exit->data_offset = run->io.data_offset;
		exit->count = run->io.count;
		exit->len = run->io.size;
		exit->direction = run->io.direction;
		if (bytes <= sizeof(exit->data) &&
		    run->io.data_offset >= PAGE_SIZE &&
		    run->io.data_offset < 2 * PAGE_SIZE &&
		    bytes <= 2 * PAGE_SIZE - run->io.data_offset)
			exit->payload_valid =
				kvm_arch_vcpu_exec_copy_pio_data(vcpu,
								 exit->data, bytes);
	} else if (run->exit_reason == KVM_EXIT_MMIO) {
		exit->address = run->mmio.phys_addr;
		exit->len = run->mmio.len;
		exit->direction = run->mmio.is_write;
	}
}

static u64 kvm_exec_next_exit_sequence_locked(struct kvm_exec_capsule *capsule)
{
	u64 sequence = ++capsule->next_exit_sequence;

	if (!sequence)
		sequence = ++capsule->next_exit_sequence;
	return sequence;
}

static void kvm_exec_record_exit_locked(struct kvm_exec_capsule *capsule,
					struct kvm_exec_exit_state *exit)
{
	bool completion_pending = exit->completion_pending;

	exit->sequence = kvm_exec_next_exit_sequence_locked(capsule);
	exit->completion_pending = false;
	capsule->exit = *exit;
	WRITE_ONCE(capsule->exit.completion_pending, completion_pending);
}

static bool kvm_exec_async_pio_write(struct kvm_exec_domain *domain,
				     struct kvm_exec_exit_state *exit)
{
	return domain->negotiated_features & KVM_EXEC_FEATURE_ASYNC_PIO_WRITE &&
	       exit->reason == KVM_EXIT_IO &&
	       exit->direction == KVM_EXIT_IO_OUT && exit->count == 1 &&
	       (exit->len == 1 || exit->len == 2 || exit->len == 4) &&
	       exit->completion_pending && exit->payload_valid &&
	       exit->data_offset >= PAGE_SIZE &&
	       exit->data_offset < 2 * PAGE_SIZE &&
	       exit->len <= 2 * PAGE_SIZE - exit->data_offset;
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

static int kvm_exec_async_ring_state(struct kvm_exec_executor *executor,
				     bool *request_full,
				     bool *has_completion)
{
	struct kvm_exec_dispatch_header *header =
		kvm_exec_dispatch_header(executor);
	u64 request_head, completion_tail;

	if (!kvm_exec_dispatch_header_valid(executor) ||
	    READ_ONCE(header->exit_request_tail) !=
			executor->exit_request_tail ||
	    READ_ONCE(header->exit_completion_head) !=
			executor->exit_completion_head)
		return kvm_exec_dispatch_corrupt(executor);

	/* Pairs with userspace's release consumption of an exit request. */
	request_head = smp_load_acquire(&header->exit_request_head);
	/* Pairs with userspace's release publication of an exit completion. */
	completion_tail = smp_load_acquire(&header->exit_completion_tail);
	if (executor->exit_request_tail - request_head >
			KVM_EXEC_DISPATCH_RING_ENTRIES ||
	    completion_tail - executor->exit_completion_head >
			KVM_EXEC_DISPATCH_RING_ENTRIES)
		return kvm_exec_dispatch_corrupt(executor);

	*request_full = executor->exit_request_tail - request_head ==
			KVM_EXEC_DISPATCH_RING_ENTRIES;
	*has_completion = completion_tail != executor->exit_completion_head;
	return 0;
}

static bool
kvm_exec_async_publish(struct kvm_exec_executor *executor,
		       struct kvm_exec_capsule *capsule)
{
	struct kvm_exec_dispatch_header *header =
		kvm_exec_dispatch_header(executor);
	struct kvm_exec_exit_request request = {
		.size = sizeof(request),
		.type = KVM_EXEC_EXIT_REQUEST_PIO_WRITE,
		.domain_generation = executor->domain->generation,
		.executor_generation = executor->generation,
		.capsule_id = capsule->capsule_id,
		.lifecycle_generation = capsule->lifecycle_generation,
		.exit_sequence = capsule->exit.sequence,
		.executor_return_count = executor->return_count,
		.published_ns = ktime_get_ns(),
		.port = capsule->exit.address,
		.width = capsule->exit.len,
		.count = capsule->exit.count,
	};
	struct kvm_exec_exit_request *slot;
	bool request_full, has_completion;
	int ret;

	ret = kvm_exec_async_ring_state(executor, &request_full,
					&has_completion);
	if (ret || request_full || has_completion) {
		WRITE_ONCE(header->async_exit_fallback_count,
			   READ_ONCE(header->async_exit_fallback_count) + 1);
		return false;
	}

	memcpy(request.data, capsule->exit.data, capsule->exit.len);
	slot = &kvm_exec_exit_requests(executor)
		[executor->exit_request_tail % KVM_EXEC_DISPATCH_RING_ENTRIES];
	memcpy(slot, &request, sizeof(request));
	executor->mapped_boundary_return_kick_epoch =
		atomic64_read(&executor->return_kick_epoch);
	capsule->exit.async_request_pending = true;
	capsule->exit.async_completion_ready = false;
	capsule->exit.async_entry_authorized = false;
	capsule->exit.async_reentry_required = true;
	executor->exit_request_tail++;
	/* The request and capsule state are visible before userspace sees tail. */
	smp_store_release(&header->exit_request_tail,
			  executor->exit_request_tail);
	WRITE_ONCE(header->async_exit_request_count,
		   READ_ONCE(header->async_exit_request_count) + 1);
	WRITE_ONCE(header->last_async_exit_sequence, capsule->exit.sequence);
	return true;
}

static int kvm_exec_async_consume(struct kvm_exec_executor *executor)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_dispatch_header *header =
		kvm_exec_dispatch_header(executor);
	struct kvm_exec_exit_completion response;
	struct kvm_exec_capsule *capsule;
	bool request_full, has_completion;
	bool valid;
	int ret;

	ret = kvm_exec_async_ring_state(executor, &request_full,
					&has_completion);
	if (ret || !has_completion)
		return ret;

	memcpy(&response,
	       &kvm_exec_exit_completions(executor)
		[executor->exit_completion_head %
		 KVM_EXEC_DISPATCH_RING_ENTRIES],
	       sizeof(response));
	executor->exit_completion_head++;
	/* Userspace may reuse the response slot after observing this head. */
	smp_store_release(&header->exit_completion_head,
			  executor->exit_completion_head);

	valid = response.size == sizeof(response) &&
		response.status == KVM_EXEC_EXIT_COMPLETE_OK &&
		!response.flags && response.completed_ns &&
		response.domain_generation == domain->generation &&
		response.executor_generation == executor->generation &&
		response.capsule_id && response.lifecycle_generation &&
		response.exit_sequence &&
		!memchr_inv(response.reserved, 0, sizeof(response.reserved));

	mutex_lock(&domain->lock);
	capsule = valid ? xa_load(&domain->capsules, response.capsule_id) : NULL;
	valid = valid && capsule && capsule->vcpu &&
		capsule->owner == executor &&
		capsule->lifecycle_generation == response.lifecycle_generation &&
		capsule->exit.sequence == response.exit_sequence &&
		capsule->exit.completion_pending &&
		capsule->exit.async_request_pending &&
		!capsule->exit.async_completion_ready;
	if (valid) {
		capsule->exit.async_request_pending = false;
		capsule->exit.async_completion_ready = true;
		capsule->exit.async_entry_authorized = false;
	}
	mutex_unlock(&domain->lock);
	if (!valid)
		return -EINVAL;

	WRITE_ONCE(header->async_exit_completion_count,
		   READ_ONCE(header->async_exit_completion_count) + 1);
	return 1;
}

static bool kvm_exec_async_blocks_entry(struct kvm_exec_capsule *capsule)
{
	return capsule->exit.async_request_pending ||
	       (capsule->exit.async_completion_ready &&
		!capsule->exit.async_entry_authorized) ||
	       capsule->exit.async_reentry_required;
}

static int
kvm_exec_async_apply_completion(struct kvm_exec_executor *executor)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_capsule *capsule;
	u8 immediate_exit;
	bool pending;
	int run_ret;

	mutex_lock(&domain->lock);
	capsule = executor->current_capsule;
	if (!capsule || !capsule->vcpu || capsule->running ||
	    !capsule->exit.completion_pending ||
	    !capsule->exit.async_completion_ready) {
		mutex_unlock(&domain->lock);
		return -EINVAL;
	}
	capsule->running = true;
	capsule->exit.async_entry_authorized = true;
	mutex_unlock(&domain->lock);

	mutex_lock(&capsule->vcpu->mutex);
	immediate_exit = READ_ONCE(capsule->vcpu->run->immediate_exit);
	WRITE_ONCE(capsule->vcpu->run->immediate_exit, 1);
	run_ret = kvm_exec_vcpu_run(executor, capsule);
	WRITE_ONCE(capsule->vcpu->run->immediate_exit, immediate_exit);
	pending = kvm_arch_vcpu_exec_completion_pending(capsule->vcpu);
	mutex_unlock(&capsule->vcpu->mutex);

	mutex_lock(&domain->lock);
	capsule->running = false;
	if (!pending) {
		WRITE_ONCE(capsule->exit.completion_pending, false);
		capsule->exit.async_request_pending = false;
		capsule->exit.async_completion_ready = false;
		capsule->exit.async_entry_authorized = false;
		atomic_cmpxchg(&capsule->block_reason, KVM_EXEC_BLOCK_VMM_EXIT,
			       KVM_EXEC_BLOCK_NONE);
	}
	mutex_unlock(&domain->lock);
	wake_up_all(&domain->drain_wait);

	if (pending)
		return -EIO;
	return run_ret == -EINTR ? 0 : -EPROTO;
}

static bool kvm_exec_exit_blocks_handoff(struct kvm_exec_capsule *capsule)
{
	return capsule->exit.completion_pending &&
	       !capsule->exit.async_completion_ready;
}

static bool
kvm_exec_interrupt_in_service(struct kvm_exec_executor *executor,
			      struct kvm_exec_capsule *capsule)
{
	struct kvm_exec_pending_interrupt interrupt = { };
	struct kvm_vcpu *vcpu;
	bool in_service;

	lockdep_assert_held(&executor->domain->lock);
	if (!kvm_exec_interrupt_snapshot(executor, &interrupt) ||
	    !kvm_exec_delivery_uses_local_apic(interrupt.delivery))
		return false;
	if (!capsule || !capsule->vcpu ||
	    capsule->capsule_id != interrupt.capsule_id ||
	    capsule->lifecycle_generation != interrupt.lifecycle_generation)
		return true;

	vcpu = capsule->vcpu;
	mutex_lock(&vcpu->mutex);
	in_service = kvm_arch_vcpu_exec_apic_in_service(vcpu, interrupt.vector);
	mutex_unlock(&vcpu->mutex);
	return in_service;
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
		.executor_return_count = executor->return_count,
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
	if (current_capsule && current_capsule->exit.async_request_pending) {
		status = KVM_EXEC_COMPLETE_EXIT_PENDING;
		goto terminal_locked;
	}
	if (current_capsule && kvm_exec_exit_blocks_handoff(current_capsule) &&
	    (command.opcode != KVM_EXEC_CMD_SWITCH ||
	     command.target_capsule_id != current_capsule->capsule_id ||
	     command.target_lifecycle_generation !=
		current_capsule->lifecycle_generation)) {
		status = KVM_EXEC_COMPLETE_EXIT_PENDING;
		goto terminal_locked;
	}
	if (current_capsule &&
	    kvm_exec_interrupt_in_service(executor, current_capsule) &&
	    (command.opcode != KVM_EXEC_CMD_SWITCH ||
	     command.target_capsule_id != current_capsule->capsule_id ||
	     command.target_lifecycle_generation !=
		current_capsule->lifecycle_generation)) {
		status = KVM_EXEC_COMPLETE_INTERRUPT_PENDING;
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
		if ((domain->negotiated_features &
		     KVM_EXEC_FEATURE_LIFECYCLE_STATE) &&
		    atomic_read(&target->block_reason) == KVM_EXEC_BLOCK_HLT) {
			status = KVM_EXEC_COMPLETE_TARGET_BLOCKED;
			goto terminal_locked;
		}
		if (target != current_capsule &&
		    kvm_exec_exit_blocks_handoff(target)) {
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
		kvm_exec_interrupt_abort(executor, true);
		if (current_capsule) {
			current_capsule->exit.async_entry_authorized = false;
			current_capsule->exit.async_reentry_required = false;
			atomic_cmpxchg(&current_capsule->block_reason,
				       KVM_EXEC_BLOCK_VMM_EXIT,
				       KVM_EXEC_BLOCK_NONE);
			current_capsule->owner = NULL;
		}
		executor->current_capsule = NULL;
		atomic64_inc(&executor->release_count);
		status = KVM_EXEC_COMPLETE_RETURNED;
	} else {
		if (current_capsule != target) {
			kvm_exec_interrupt_abort(executor, true);
			if (current_capsule) {
				current_capsule->exit.async_entry_authorized = false;
				current_capsule->exit.async_reentry_required = false;
				current_capsule->owner = NULL;
			}
			target->owner = executor;
			executor->current_capsule = target;
			atomic64_inc(&executor->switch_count);
		}
		atomic_cmpxchg(&target->block_reason, KVM_EXEC_BLOCK_VMM_EXIT,
			       KVM_EXEC_BLOCK_NONE);
		if (target->exit.async_completion_ready)
			target->exit.async_entry_authorized = true;
		target->exit.async_reentry_required = false;
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
	if (status == KVM_EXEC_COMPLETE_CANCELLED_BEFORE_APPLY)
		atomic64_inc(&executor->cancelled_count);
	else
		atomic64_inc(&executor->rejected_count);
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
	u64 command_tail, exit_completion_tail;

	/* Pairs with userspace's release publication of a command entry. */
	command_tail = smp_load_acquire(&header->command_tail);
	/* Pairs with userspace's release publication of an exit completion. */
	exit_completion_tail = smp_load_acquire(&header->exit_completion_tail);
	return READ_ONCE(executor->domain->paused) ||
	       READ_ONCE(executor->domain->stopping) ||
	       atomic64_read(&executor->kick_epoch) != kick_epoch ||
	       command_tail != executor->command_head ||
	       exit_completion_tail != executor->exit_completion_head;
}

static bool kvm_exec_consume_return_kick(struct kvm_exec_executor *executor)
{
	u64 epoch = atomic64_read(&executor->return_kick_epoch);

	if (epoch == executor->consumed_return_kick_epoch)
		return false;
	executor->consumed_return_kick_epoch = epoch;
	return executor->mapped_boundary_return_kick_epoch < epoch;
}

static bool
kvm_exec_interrupt_snapshot(struct kvm_exec_executor *executor,
			    struct kvm_exec_pending_interrupt *interrupt)
{
	unsigned long flags;
	bool pending;

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	pending = executor->pending_interrupt_sequence != 0;
	if (pending && interrupt) {
		interrupt->sequence = executor->pending_interrupt_sequence;
		interrupt->capsule_id = executor->pending_interrupt_capsule_id;
		interrupt->lifecycle_generation =
			executor->pending_interrupt_lifecycle_generation;
		interrupt->vector = executor->pending_interrupt_vector;
		interrupt->flags = executor->pending_interrupt_flags;
		interrupt->delivery = executor->pending_interrupt_delivery;
	}
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);
	return pending;
}

static void
kvm_exec_interrupt_finish(struct kvm_exec_executor *executor, u64 sequence,
			  bool applied)
{
	unsigned long flags;

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	if (executor->pending_interrupt_sequence == sequence) {
		executor->pending_interrupt_sequence = 0;
		executor->pending_interrupt_capsule_id = 0;
		executor->pending_interrupt_lifecycle_generation = 0;
		executor->pending_interrupt_vector = 0;
		executor->pending_interrupt_flags = 0;
		executor->pending_interrupt_delivery = 0;
		executor->pending_interrupt_arch_queued = false;
		executor->pending_interrupt_handler_observed = false;
		if (applied)
			executor->interrupt_applied_count++;
	}
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);
}

static void kvm_exec_interrupt_set_queued(struct kvm_exec_executor *executor,
					  u64 sequence)
{
	unsigned long flags;

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	if (executor->pending_interrupt_sequence == sequence)
		executor->pending_interrupt_arch_queued = true;
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);
}

static bool
kvm_exec_interrupt_arch_queued(struct kvm_exec_executor *executor, u64 sequence)
{
	unsigned long flags;
	bool queued;

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	queued = executor->pending_interrupt_sequence == sequence &&
		 executor->pending_interrupt_arch_queued;
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);
	return queued;
}

static void
kvm_exec_interrupt_retain_halt(struct kvm_exec_executor *executor,
			       const struct kvm_exec_pending_interrupt *interrupt)
{
	unsigned long flags;

	if (!(interrupt->flags & KVM_EXEC_INTERRUPT_F_RETAIN_HLT))
		return;
	spin_lock_irqsave(&executor->interrupt_lock, flags);
	executor->retained_halt_capsule_id = interrupt->capsule_id;
	executor->retained_halt_lifecycle_generation =
		interrupt->lifecycle_generation;
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);
}

static void kvm_exec_interrupt_clear_retained_halt(
	struct kvm_exec_executor *executor)
{
	unsigned long flags;

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	executor->retained_halt_capsule_id = 0;
	executor->retained_halt_lifecycle_generation = 0;
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);
}

static bool kvm_exec_interrupt_consume_retained_halt(
	struct kvm_exec_executor *executor, struct kvm_exec_capsule *capsule)
{
	unsigned long flags;
	bool retain;

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	retain = executor->retained_halt_capsule_id == capsule->capsule_id &&
		executor->retained_halt_lifecycle_generation ==
			capsule->lifecycle_generation;
	if (retain) {
		executor->retained_halt_capsule_id = 0;
		executor->retained_halt_lifecycle_generation = 0;
	}
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);
	return retain;
}

static void kvm_exec_interrupt_abort(struct kvm_exec_executor *executor,
				     bool superseded)
{
	struct kvm_exec_pending_interrupt interrupt = { };
	struct kvm_exec_capsule *capsule;
	struct kvm_vcpu *vcpu;

	lockdep_assert_held(&executor->domain->lock);
	if (kvm_exec_interrupt_snapshot(executor, &interrupt)) {
		if (interrupt.delivery ==
		    KVM_EXEC_INTERRUPT_DELIVERY_DIRECT_KICK) {
			capsule = executor->current_capsule;
			if (capsule && capsule->vcpu &&
			    capsule->capsule_id == interrupt.capsule_id &&
			    capsule->lifecycle_generation ==
				interrupt.lifecycle_generation) {
				vcpu = capsule->vcpu;
				mutex_lock(&vcpu->mutex);
				kvm_arch_vcpu_exec_cancel_direct(vcpu, interrupt.vector);
				mutex_unlock(&vcpu->mutex);
			}
		} else if (kvm_exec_delivery_uses_local_apic(interrupt.delivery)) {
			capsule = executor->current_capsule;
			if (capsule && capsule->vcpu &&
			    capsule->capsule_id == interrupt.capsule_id &&
			    capsule->lifecycle_generation ==
				interrupt.lifecycle_generation) {
				mutex_lock(&capsule->vcpu->mutex);
				kvm_arch_vcpu_exec_cancel_local_apic_interrupt(
					capsule->vcpu, interrupt.vector);
				mutex_unlock(&capsule->vcpu->mutex);
			}
			if (interrupt.delivery ==
			    KVM_EXEC_INTERRUPT_DELIVERY_POSTED) {
				unsigned long flags;

				spin_lock_irqsave(&executor->interrupt_lock, flags);
				if (superseded)
					executor->interrupt_posted_superseded_count++;
				else
					executor->interrupt_posted_disarmed_count++;
				spin_unlock_irqrestore(&executor->interrupt_lock, flags);
			}
		}
		kvm_exec_interrupt_finish(executor, interrupt.sequence, false);
	}
	kvm_exec_interrupt_clear_retained_halt(executor);
}

void kvm_exec_domain_apic_interrupt_delivered(struct kvm_vcpu *vcpu,
					       u32 vector)
{
	struct kvm_exec_capsule *capsule = READ_ONCE(vcpu->exec_capsule);
	struct kvm_exec_executor *executor;
	unsigned long flags;

	if (!capsule)
		return;
	executor = READ_ONCE(capsule->owner);
	if (!executor)
		return;

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	if (executor->pending_interrupt_sequence &&
	    kvm_exec_delivery_uses_local_apic(
		executor->pending_interrupt_delivery) &&
	    executor->pending_interrupt_capsule_id == capsule->capsule_id &&
	    executor->pending_interrupt_lifecycle_generation ==
		capsule->lifecycle_generation &&
	    executor->pending_interrupt_vector == vector &&
	    !executor->pending_interrupt_handler_observed) {
		executor->pending_interrupt_handler_observed = true;
		executor->interrupt_handler_delivery_count++;
	}
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);
}

void kvm_exec_domain_apic_eoi(struct kvm_vcpu *vcpu, u32 vector)
{
	struct kvm_exec_capsule *capsule = READ_ONCE(vcpu->exec_capsule);
	struct kvm_exec_executor *executor;
	unsigned long flags;
	bool retired = false;

	if (!capsule)
		return;
	executor = READ_ONCE(capsule->owner);
	if (!executor)
		return;

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	if (executor->pending_interrupt_sequence &&
	    kvm_exec_delivery_uses_local_apic(
		executor->pending_interrupt_delivery) &&
	    executor->pending_interrupt_capsule_id == capsule->capsule_id &&
	    executor->pending_interrupt_lifecycle_generation ==
		capsule->lifecycle_generation &&
	    executor->pending_interrupt_vector == vector &&
	    executor->pending_interrupt_handler_observed) {
		if (executor->pending_interrupt_delivery ==
		    KVM_EXEC_INTERRUPT_DELIVERY_POSTED) {
			u64 exits = kvm_arch_exec_posted_notification_exits(
				executor->last_interrupt_notification_cpu);

			executor->interrupt_posted_target_exit_count +=
				(u32)exits -
				(u32)executor->interrupt_posted_target_exit_baseline;
			executor->interrupt_posted_target_exit_baseline = exits;
		}
		executor->pending_interrupt_sequence = 0;
		executor->pending_interrupt_capsule_id = 0;
		executor->pending_interrupt_lifecycle_generation = 0;
		executor->pending_interrupt_vector = 0;
		executor->pending_interrupt_flags = 0;
		executor->pending_interrupt_delivery = 0;
		executor->pending_interrupt_handler_observed = false;
		executor->interrupt_applied_count++;
		executor->interrupt_eoi_count++;
		retired = true;
	}
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);
	if (retired)
		wake_up_interruptible(&executor->dispatch_wait);
}

static void
kvm_exec_refresh_direct_interrupt(struct kvm_exec_executor *executor,
				  struct kvm_vcpu *vcpu)
{
	struct kvm_exec_pending_interrupt interrupt = { };

	if (!kvm_exec_interrupt_snapshot(executor, &interrupt) ||
	    interrupt.delivery != KVM_EXEC_INTERRUPT_DELIVERY_DIRECT_KICK ||
	    !kvm_exec_interrupt_arch_queued(executor, interrupt.sequence) ||
	    kvm_arch_vcpu_exec_direct_pending(vcpu, interrupt.vector))
		return;

	/*
	 * Direct delivery first queues the exact vector in KVM's ordinary
	 * interrupt state.  Keep ownership of that vector until a run boundary
	 * proves that KVM no longer needs to inject or reinject it.  An ownership
	 * command that wins before then can cancel the still-queued vector instead
	 * of leaking it into a later re-entry of the old capsule.
	 */
	kvm_exec_interrupt_finish(executor, interrupt.sequence, true);
}

static void
kvm_exec_refresh_posted_interrupt(struct kvm_exec_executor *executor,
				  struct kvm_vcpu *vcpu)
{
	struct kvm_exec_pending_interrupt interrupt = { };

	if (!kvm_exec_interrupt_snapshot(executor, &interrupt) ||
	    interrupt.delivery != KVM_EXEC_INTERRUPT_DELIVERY_POSTED ||
	    kvm_arch_vcpu_exec_apic_interrupt_pending(vcpu, interrupt.vector))
		return;

	/*
	 * APICv delivers a posted vector without traversing the software LAPIC
	 * acceptance hook.  At a later VM boundary, an empty PIR/IRR/ISR set is
	 * proof that hardware delivered the vector and the guest issued EOI.
	 * Observe and retire that exact request without forcing a delivery exit.
	 */
	kvm_exec_domain_apic_interrupt_delivered(vcpu, interrupt.vector);
	kvm_exec_domain_apic_eoi(vcpu, interrupt.vector);
}

static bool kvm_exec_dispatch_failed(const struct kvm_exec_run_dispatch *run)
{
	if (run->return_reason == KVM_EXEC_RETURN_DISPATCH_EMPTY)
		return !(run->flags & KVM_EXEC_DISPATCH_F_RETURN_IF_EMPTY);

	return run->return_reason == KVM_EXEC_RETURN_CPU_MIGRATED ||
	       run->return_reason == KVM_EXEC_RETURN_COMPLETION_FULL ||
	       run->return_reason == KVM_EXEC_RETURN_DISPATCH_CORRUPT ||
	       run->return_reason == KVM_EXEC_RETURN_INVALID_COMPLETION;
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
	/*
	 * A forced return is a distinct userspace service boundary even when it
	 * does not replace capsule->exit.  Allocate its tag in the kernel so it
	 * cannot collide with the next architectural KVM exit.  A return while a
	 * read completion is still pending must retain the issuing exit's tag.
	 */
	if (run->return_reason == KVM_EXEC_RETURN_SIGNAL &&
	    !capsule->exit.completion_pending) {
		run->exit_sequence =
			kvm_exec_next_exit_sequence_locked(capsule);
		return;
	}
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
	int async_ret, command_ret, run_ret, ret;

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
		struct kvm_exec_pending_interrupt pending_interrupt = { };
		bool attempted_kvm_run = false;
		bool entry_allowed;
		bool invalid_completion = false;
		bool async_published = false;
		bool pending_after_run = false;
		bool interrupt_pending;
		bool interrupt_waiting = false;
		bool interrupt_failed = false;
		bool interrupt_window_exit = false;
		bool kick_pending;
		bool retained_halt_exit = false;
		bool return_to_vmm;
		bool strict_migrated;
		u32 reported_exit_reason;
		int interrupt_ret = 0;

		mutex_lock(&domain->lock);
		if (domain->stopping || domain->paused) {
			kvm_exec_interrupt_abort(executor, false);
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

		mutex_lock(&domain->lock);
		capsule = executor->current_capsule;
		return_to_vmm = kvm_exec_consume_return_kick(executor);
		if (return_to_vmm) {
			run.return_reason = KVM_EXEC_RETURN_SIGNAL;
			run.run_result = -EINTR;
			mutex_unlock(&domain->lock);
			break;
		}
		mutex_unlock(&domain->lock);

		async_ret = 0;
		if (domain->negotiated_features &
		    KVM_EXEC_FEATURE_ASYNC_PIO_WRITE)
			async_ret = kvm_exec_async_consume(executor);
		if (async_ret == -EPROTO) {
			run.return_reason = KVM_EXEC_RETURN_DISPATCH_CORRUPT;
			run.run_result = -EPROTO;
			break;
		}
		if (async_ret < 0) {
			run.return_reason = KVM_EXEC_RETURN_INVALID_COMPLETION;
			run.run_result = async_ret;
			break;
		}
		if (async_ret > 0) {
			async_ret = kvm_exec_async_apply_completion(executor);
			if (async_ret) {
				run.return_reason =
					KVM_EXEC_RETURN_INVALID_COMPLETION;
				run.run_result = async_ret;
				break;
			}
		}

		/*
		 * A direct interrupt may wait indefinitely for an open guest
		 * window, so its ownership change remains consumable.  A queued
		 * local-APIC interrupt is rejected by command validation until the
		 * guest retires it with EOI.
		 */
		command_ret = 0;
		if (!completion_pending) {
			bool command_blocked;

			mutex_lock(&domain->lock);
			capsule = executor->current_capsule;
			command_blocked = capsule &&
				capsule->exit.async_request_pending;
			mutex_unlock(&domain->lock);
			if (command_blocked)
				goto command_done;
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
command_done:
		interrupt_pending =
			kvm_exec_interrupt_snapshot(executor,
						    &pending_interrupt);
		mutex_lock(&domain->lock);
		if (domain->stopping) {
			kvm_exec_interrupt_abort(executor, false);
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
			kvm_exec_interrupt_abort(executor, false);
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
		if ((domain->negotiated_features &
		     KVM_EXEC_FEATURE_LIFECYCLE_STATE) &&
		    atomic_read(&capsule->block_reason) ==
		    KVM_EXEC_BLOCK_HLT && !interrupt_pending) {
			mutex_unlock(&domain->lock);
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
		if (kvm_exec_async_blocks_entry(capsule)) {
			mutex_unlock(&domain->lock);
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
		/*
		 * A dispatcher kick can race with the transition between two
		 * kvm_vcpu_run() calls.  Remove any request left by a kick that the
		 * dispatcher has already observed, then order that removal before the
		 * final epoch check.  A later kick either changes the epoch and blocks
		 * entry or observes capsule->running and interrupts the new run.
		 */
		kvm_clear_request(KVM_REQ_EXEC_DOMAIN_EXIT, capsule->vcpu);
		/* Order the request removal before reading the writer's epoch. */
		smp_mb__after_atomic();
		kick_pending = atomic64_read(&executor->kick_epoch) !=
			       seen_kick_epoch;
		entry_allowed = !READ_ONCE(domain->stopping) &&
				!READ_ONCE(domain->paused) &&
				!kick_pending &&
				capsule->vcpu->exec_capsule == capsule &&
				kvm_arch_vcpu_exec_domain_supported(capsule->vcpu) &&
				!kvm_exec_async_blocks_entry(capsule);
		if (entry_allowed && capsule->exit.completion_pending &&
		    !kvm_exec_pending_exit_valid(capsule)) {
			entry_allowed = false;
			invalid_completion = true;
		}
		interrupt_pending =
			kvm_exec_interrupt_snapshot(executor,
						    &pending_interrupt);
		if (entry_allowed && interrupt_pending &&
		    kvm_exec_delivery_uses_local_apic(
			pending_interrupt.delivery)) {
			if (pending_interrupt.capsule_id != capsule->capsule_id ||
			    pending_interrupt.lifecycle_generation !=
				    capsule->lifecycle_generation) {
				interrupt_ret = -ESTALE;
				kvm_exec_interrupt_finish(
					executor, pending_interrupt.sequence, false);
				interrupt_failed = true;
				entry_allowed = false;
			}
		} else if (entry_allowed && interrupt_pending) {
			if (pending_interrupt.capsule_id != capsule->capsule_id ||
			    pending_interrupt.lifecycle_generation !=
				    capsule->lifecycle_generation) {
				interrupt_ret = -ESTALE;
			} else {
				interrupt_ret =
					kvm_arch_vcpu_exec_inject_interrupt(
						capsule->vcpu,
						pending_interrupt.vector);
			}
			if (!interrupt_ret) {
				kvm_exec_interrupt_set_queued(executor, pending_interrupt.sequence);
				kvm_exec_interrupt_retain_halt(
					executor, &pending_interrupt);
				if (atomic_cmpxchg(&capsule->block_reason,
						   KVM_EXEC_BLOCK_HLT,
						   KVM_EXEC_BLOCK_NONE) ==
				    KVM_EXEC_BLOCK_HLT)
					atomic64_inc(&capsule->wake_count);
			} else if (interrupt_ret == -EAGAIN) {
				interrupt_waiting = true;
			} else {
				kvm_exec_interrupt_finish(
					executor, pending_interrupt.sequence, false);
				interrupt_failed = true;
				entry_allowed = false;
			}
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
			run_ret = kvm_exec_vcpu_run(executor, capsule);
			kvm_exec_refresh_direct_interrupt(executor, capsule->vcpu);
			kvm_exec_refresh_posted_interrupt(executor,
							  capsule->vcpu);
			reported_exit_reason = capsule->vcpu->run->exit_reason;
			pending_after_run =
				kvm_arch_vcpu_exec_completion_pending(capsule->vcpu);
			if (!run_ret)
				kvm_exec_snapshot_exit(capsule->vcpu,
						       &observed_exit);
		}
		interrupt_window_exit =
			attempted_kvm_run && !run_ret && interrupt_waiting &&
			reported_exit_reason == KVM_EXIT_IRQ_WINDOW_OPEN;
		final_cpu = get_cpu();
		put_cpu();
		strict_migrated =
			(executor->flags & KVM_EXECUTOR_F_STRICT_CPU) &&
			final_cpu != executor->requested_cpu;
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
		if (interrupt_failed) {
			run.run_result = interrupt_ret;
			run.return_reason = KVM_EXEC_RETURN_INTERRUPT_FAILED;
			atomic64_inc(&executor->failure_count);
			mutex_unlock(&domain->lock);
			break;
		}
		if (!run_ret && !interrupt_window_exit) {
			kvm_exec_account_exit(executor, capsule,
					      observed_exit.reason);
			kvm_exec_record_exit_locked(capsule, &observed_exit);
			if (!strict_migrated && !domain->stopping && !domain->paused &&
			    kvm_exec_async_pio_write(domain, &capsule->exit))
				async_published =
					kvm_exec_async_publish(executor, capsule);
			if (observed_exit.reason == KVM_EXIT_HLT)
				retained_halt_exit =
					kvm_exec_interrupt_consume_retained_halt(
						executor, capsule);
			else if (!async_published &&
				 observed_exit.reason != KVM_EXIT_DEBUG)
				kvm_exec_interrupt_clear_retained_halt(
					executor);
		} else if (attempted_kvm_run &&
			   capsule->exit.completion_pending &&
			   !pending_after_run) {
			WRITE_ONCE(capsule->exit.completion_pending, false);
			capsule->exit.async_request_pending = false;
			capsule->exit.async_completion_ready = false;
			capsule->exit.async_entry_authorized = false;
		}
		if (domain->stopping) {
			kvm_exec_interrupt_abort(executor, false);
			run.return_reason = KVM_EXEC_RETURN_DOMAIN_STOPPING;
			mutex_unlock(&domain->lock);
			break;
		}
		if (domain->paused) {
			kvm_exec_interrupt_abort(executor, false);
			run.return_reason = KVM_EXEC_RETURN_DOMAIN_PAUSED;
			mutex_unlock(&domain->lock);
			break;
		}
		mutex_unlock(&domain->lock);

		if (strict_migrated) {
			struct kvm_exec_pending_interrupt interrupt;

			mutex_lock(&domain->lock);
			if (kvm_exec_interrupt_snapshot(executor, &interrupt) &&
			    interrupt.delivery == KVM_EXEC_INTERRUPT_DELIVERY_POSTED)
				domain->stopping = true;
			kvm_exec_interrupt_abort(executor, false);
			mutex_unlock(&domain->lock);
			run.return_reason = KVM_EXEC_RETURN_CPU_MIGRATED;
			break;
		}
		if (retained_halt_exit)
			continue;
		if (interrupt_window_exit)
			continue;
		if (async_published)
			continue;
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
	kvm_exec_interrupt_clear_retained_halt(executor);
	kvm_exec_dispatch_run_owner(executor, &run);
	if (active)
		atomic_dec(&domain->active_runs);
	mutex_unlock(&domain->lock);
	wake_up_all(&domain->drain_wait);
	run.command_head = executor->command_head;
	run.completion_tail = executor->completion_tail;
	run.corruption_count = executor->corruption_count;
	run.reserved0 = 0;
	executor->return_count++;
	WRITE_ONCE(header->executor_return_count, executor->return_count);
	if (kvm_exec_dispatch_failed(&run))
		atomic64_inc(&executor->failure_count);
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
	if (kick.size != sizeof(kick) ||
	    kick.flags & ~KVM_EXEC_KICK_F_RETURN_TO_VMM ||
	    !kick.request_sequence ||
	    memchr_inv(kick.reserved, 0, sizeof(kick.reserved)))
		return -EINVAL;
	ret = kvm_exec_domain_access(domain);
	if (ret)
		return ret;
	if (!(domain->negotiated_features & KVM_EXEC_FEATURE_DYNAMIC_DISPATCH))
		return -EOPNOTSUPP;
	if ((kick.flags & KVM_EXEC_KICK_F_RETURN_TO_VMM) &&
	    !(domain->negotiated_features & KVM_EXEC_FEATURE_RETURN_KICK))
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
	capsule = executor->current_capsule;
	if (kick.flags & KVM_EXEC_KICK_F_RETURN_TO_VMM) {
		u64 return_epoch =
			atomic64_inc_return(&executor->return_kick_epoch);

		/*
		 * A mapped exit is already a userspace-visible service boundary.
		 * If the return request races behind its publication, satisfy the
		 * request at that boundary instead of forcing a redundant ioctl
		 * return before the next exact command.
		 */
		if (capsule && capsule->exit.async_request_pending)
			executor->mapped_boundary_return_kick_epoch =
				return_epoch;
	}
	header = kvm_exec_dispatch_header(executor);
	WRITE_ONCE(header->kernel_kick_count, epoch);
	WRITE_ONCE(header->last_kick_sequence, kick.request_sequence);
	WRITE_ONCE(header->last_kick_ns, ktime_get_ns());

	if (capsule && capsule->running) {
		kvm_make_request(KVM_REQ_EXEC_DOMAIN_EXIT, capsule->vcpu);
		kvm_make_request(KVM_REQ_UNBLOCK, capsule->vcpu);
		kvm_vcpu_kick(capsule->vcpu);
	}
	mutex_unlock(&domain->lock);
	wake_up_interruptible(&executor->dispatch_wait);
	return 0;
}

#define KVM_EXEC_INTERRUPT_TRACE_ACCEPTED	1U
#define KVM_EXEC_INTERRUPT_TRACE_DELIVERED	2U

static int
kvm_exec_validate_interrupt_locked(struct kvm_exec_executor *executor,
				   const struct kvm_exec_interrupt_request *request,
				   struct kvm_exec_capsule **target)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_capsule *capsule;

	lockdep_assert_held(&domain->lock);
	if (domain->stopping)
		return -ESHUTDOWN;
	if (domain->paused)
		return -EBUSY;

	capsule = executor->current_capsule;
	if (!capsule ||
	    capsule->capsule_id != request->capsule_id ||
	    capsule->lifecycle_generation != request->lifecycle_generation)
		return -ESTALE;
	if (!capsule->running || capsule->exit.completion_pending ||
	    capsule->exit.async_request_pending)
		return -EAGAIN;

	*target = capsule;
	return 0;
}

static int
kvm_exec_accept_interrupt_locked(struct kvm_exec_executor *executor,
				 const struct kvm_exec_interrupt_request *request,
				 u64 *accepted_ns, u64 *accepted_tsc)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	if (request->request_sequence <= executor->last_interrupt_sequence) {
		ret = -ESTALE;
	} else if (executor->pending_interrupt_sequence) {
		ret = -EBUSY;
	} else {
		*accepted_ns = ktime_get_ns();
		*accepted_tsc = kvm_arch_exec_host_tsc();
		executor->last_interrupt_sequence = request->request_sequence;
		executor->pending_interrupt_sequence = request->request_sequence;
		executor->pending_interrupt_capsule_id = request->capsule_id;
		executor->pending_interrupt_lifecycle_generation =
			request->lifecycle_generation;
		executor->pending_interrupt_vector = request->vector;
		executor->pending_interrupt_flags = request->flags;
		executor->pending_interrupt_delivery = request->requested_delivery;
		executor->pending_interrupt_arch_queued = false;
		executor->pending_interrupt_handler_observed = false;
		executor->interrupt_queued_count++;
		executor->last_interrupt_accepted_ns = *accepted_ns;
		executor->last_interrupt_accepted_tsc = *accepted_tsc;
		ret = 0;
	}
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);
	return ret;
}

static void
kvm_exec_deliver_interrupt_direct_kick_locked(
	struct kvm_exec_executor *executor,
	const struct kvm_exec_interrupt_request *request,
	struct kvm_exec_capsule *capsule)
{
	struct kvm_exec_dispatch_header *header;
	unsigned long flags;
	u64 delivered_ns;
	u64 delivered_tsc;
	u64 epoch;

	lockdep_assert_held(&executor->domain->lock);
	delivered_ns = ktime_get_ns();
	delivered_tsc = kvm_arch_exec_host_tsc();
	epoch = atomic64_inc_return(&executor->kick_epoch);
	header = kvm_exec_dispatch_header(executor);
	WRITE_ONCE(header->kernel_kick_count, epoch);
	WRITE_ONCE(header->last_kick_sequence, request->request_sequence);
	WRITE_ONCE(header->last_kick_ns, delivered_ns);
	kvm_make_request(KVM_REQ_EXEC_DOMAIN_EXIT, capsule->vcpu);
	kvm_make_request(KVM_REQ_UNBLOCK, capsule->vcpu);
	kvm_vcpu_kick(capsule->vcpu);

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	executor->interrupt_delivery_count++;
	executor->interrupt_forced_kick_count++;
	executor->last_interrupt_delivered_ns = delivered_ns;
	executor->last_interrupt_delivered_tsc = delivered_tsc;
	executor->last_interrupt_delivery =
		KVM_EXEC_INTERRUPT_DELIVERY_DIRECT_KICK;
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);

	trace_kvm_exec_interrupt_publication(
		executor->domain->generation, executor->generation,
		executor->cookie, request->capsule_id,
		request->lifecycle_generation, request->request_sequence,
		request->vector, KVM_EXEC_INTERRUPT_TRACE_DELIVERED,
		delivered_ns);
}

static int
kvm_exec_deliver_interrupt_local_apic_locked(
	struct kvm_exec_executor *executor,
	const struct kvm_exec_interrupt_request *request,
	struct kvm_exec_capsule *capsule)
{
	unsigned long flags;
	u64 delivered_ns;
	u64 delivered_tsc;
	bool coalesced = false;
	int ret;

	lockdep_assert_held(&executor->domain->lock);
	/*
	 * This ioctl intentionally runs concurrently with the persistent task's
	 * KVM_RUN.  Taking vcpu->mutex here would wait for that run to return,
	 * while the vector and kick below are what make it return.  The LAPIC
	 * injection path is already designed for cross-vCPU callers and provides
	 * its own atomic IRR synchronization.
	 */
	ret = kvm_arch_vcpu_exec_queue_local_apic_interrupt(
		capsule->vcpu, request->vector, &coalesced);
	if (ret)
		return ret;

	delivered_ns = ktime_get_ns();
	delivered_tsc = kvm_arch_exec_host_tsc();
	if (atomic_cmpxchg(&capsule->block_reason, KVM_EXEC_BLOCK_HLT,
			   KVM_EXEC_BLOCK_NONE) == KVM_EXEC_BLOCK_HLT)
		atomic64_inc(&capsule->wake_count);
	kvm_exec_interrupt_retain_halt(
		executor,
		&(struct kvm_exec_pending_interrupt) {
			.sequence = request->request_sequence,
			.capsule_id = request->capsule_id,
			.lifecycle_generation = request->lifecycle_generation,
			.vector = request->vector,
			.flags = request->flags,
			.delivery = request->requested_delivery,
		});

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	executor->interrupt_delivery_count++;
	executor->interrupt_vector_queued_count++;
	executor->interrupt_forced_kick_count++;
	if (coalesced)
		executor->interrupt_coalesced_count++;
	executor->last_interrupt_delivered_ns = delivered_ns;
	executor->last_interrupt_delivered_tsc = delivered_tsc;
	executor->last_interrupt_delivery = coalesced ?
		KVM_EXEC_INTERRUPT_DELIVERY_COALESCED :
		KVM_EXEC_INTERRUPT_DELIVERY_LOCAL_APIC_KICK;
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);

	trace_kvm_exec_interrupt_publication(
		executor->domain->generation, executor->generation,
		executor->cookie, request->capsule_id,
		request->lifecycle_generation, request->request_sequence,
		request->vector, KVM_EXEC_INTERRUPT_TRACE_DELIVERED,
		delivered_ns);
	return 0;
}

static int
kvm_exec_deliver_interrupt_posted_locked(
	struct kvm_exec_executor *executor,
	const struct kvm_exec_interrupt_request *request,
	struct kvm_exec_capsule *capsule)
{
	unsigned long flags;
	u64 delivered_ns;
	u64 delivered_tsc;
	bool coalesced = false;
	u32 notification_cpu;
	u64 target_exit_baseline;
	int ret;

	lockdep_assert_held(&executor->domain->lock);
	/*
	 * Strict posted delivery is attempted only while the exact capsule is in
	 * guest mode.  The architecture hook must not queue through the ordinary
	 * LAPIC path or kick a root-mode vCPU when that condition has changed.
	 */
	notification_cpu = READ_ONCE(capsule->vcpu->cpu);
	target_exit_baseline =
		kvm_arch_exec_posted_notification_exits(notification_cpu);
	ret = kvm_arch_vcpu_exec_queue_posted_interrupt(
		capsule->vcpu, request->vector, &coalesced);
	if (ret) {
		spin_lock_irqsave(&executor->interrupt_lock, flags);
		if (ret == -EAGAIN)
			executor->interrupt_posted_root_rejection_count++;
		else if (ret == -EOPNOTSUPP)
			executor->interrupt_posted_inactive_rejection_count++;
		spin_unlock_irqrestore(&executor->interrupt_lock, flags);
		return ret;
	}

	delivered_ns = ktime_get_ns();
	delivered_tsc = kvm_arch_exec_host_tsc();
	if (atomic_cmpxchg(&capsule->block_reason, KVM_EXEC_BLOCK_HLT,
			   KVM_EXEC_BLOCK_NONE) == KVM_EXEC_BLOCK_HLT)
		atomic64_inc(&capsule->wake_count);
	kvm_exec_interrupt_retain_halt(
		executor,
		&(struct kvm_exec_pending_interrupt) {
			.sequence = request->request_sequence,
			.capsule_id = request->capsule_id,
			.lifecycle_generation = request->lifecycle_generation,
			.vector = request->vector,
			.flags = request->flags,
			.delivery = request->requested_delivery,
		});

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	executor->interrupt_delivery_count++;
	executor->interrupt_vector_queued_count++;
	executor->interrupt_posted_count++;
	if (coalesced) {
		executor->interrupt_coalesced_count++;
		executor->interrupt_posted_coalesced_count++;
	}
	executor->last_interrupt_delivered_ns = delivered_ns;
	executor->last_interrupt_delivered_tsc = delivered_tsc;
	executor->last_interrupt_notification_cpu = notification_cpu;
	executor->interrupt_posted_target_exit_baseline =
		target_exit_baseline;
	executor->last_interrupt_delivery = coalesced ?
		KVM_EXEC_INTERRUPT_DELIVERY_COALESCED :
		KVM_EXEC_INTERRUPT_DELIVERY_POSTED;
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);

	trace_kvm_exec_interrupt_publication(
		executor->domain->generation, executor->generation,
		executor->cookie, request->capsule_id,
		request->lifecycle_generation, request->request_sequence,
		request->vector, KVM_EXEC_INTERRUPT_TRACE_DELIVERED,
		delivered_ns);
	return 0;
}

static int
kvm_exec_submit_interrupt(struct kvm_exec_executor *executor,
			  const struct kvm_exec_interrupt_request *request)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_capsule *capsule;
	u64 accepted_ns = 0;
	u64 accepted_tsc = 0;
	int ret;

	ret = kvm_exec_domain_access(domain);
	if (ret)
		return ret;
	if (!(domain->negotiated_features & KVM_EXEC_FEATURE_EXACT_INTERRUPT))
		return -EOPNOTSUPP;
	if (request->domain_generation != domain->generation ||
	    request->executor_generation != executor->generation)
		return -ESTALE;
	if (request->requested_delivery != domain->interrupt_delivery)
		return -EINVAL;

	mutex_lock(&domain->lock);
	ret = kvm_exec_validate_interrupt_locked(executor, request, &capsule);
	if (ret)
		goto out;
	ret = kvm_exec_accept_interrupt_locked(executor, request, &accepted_ns,
					       &accepted_tsc);
	if (ret)
		goto out;

	trace_kvm_exec_interrupt_publication(
		domain->generation, executor->generation, executor->cookie,
		request->capsule_id, request->lifecycle_generation,
		request->request_sequence, request->vector,
		KVM_EXEC_INTERRUPT_TRACE_ACCEPTED, accepted_ns);
	if (request->requested_delivery ==
	    KVM_EXEC_INTERRUPT_DELIVERY_DIRECT_KICK) {
		kvm_exec_deliver_interrupt_direct_kick_locked(
			executor, request, capsule);
	} else if (request->requested_delivery ==
		   KVM_EXEC_INTERRUPT_DELIVERY_LOCAL_APIC_KICK) {
		ret = kvm_exec_deliver_interrupt_local_apic_locked(
			executor, request, capsule);
	} else if (request->requested_delivery ==
		   KVM_EXEC_INTERRUPT_DELIVERY_POSTED) {
		ret = kvm_exec_deliver_interrupt_posted_locked(
			executor, request, capsule);
	} else {
		ret = -EOPNOTSUPP;
	}
	if (ret)
		kvm_exec_interrupt_finish(
			executor, request->request_sequence, false);
out:
	if (ret) {
		unsigned long flags;

		spin_lock_irqsave(&executor->interrupt_lock, flags);
		executor->interrupt_rejection_count++;
		if (request->requested_delivery ==
			    KVM_EXEC_INTERRUPT_DELIVERY_POSTED &&
		    ret == -ESTALE)
			executor->interrupt_posted_stale_rejection_count++;
		spin_unlock_irqrestore(&executor->interrupt_lock, flags);
	}
	mutex_unlock(&domain->lock);
	if (!ret)
		wake_up_interruptible(&executor->dispatch_wait);
	return ret;
}

static struct kvm_exec_notification_header *
kvm_exec_notification_header(struct kvm_exec_notification_runner *runner)
{
	return runner->region;
}

static struct kvm_exec_notification_command *
kvm_exec_notification_commands(struct kvm_exec_notification_runner *runner)
{
	return runner->region + KVM_EXEC_NOTIFICATION_COMMAND_OFFSET;
}

static struct kvm_exec_notification_completion *
kvm_exec_notification_completions(struct kvm_exec_notification_runner *runner)
{
	return runner->region + KVM_EXEC_NOTIFICATION_COMPLETION_OFFSET;
}

static void
kvm_exec_notification_region_init(struct kvm_exec_notification_runner *runner)
{
	struct kvm_exec_notification_header *header =
		kvm_exec_notification_header(runner);

	header->abi_version = KVM_EXEC_NOTIFICATION_ABI_VERSION;
	header->region_size = KVM_EXEC_NOTIFICATION_MMAP_SIZE;
	header->command_offset = KVM_EXEC_NOTIFICATION_COMMAND_OFFSET;
	header->completion_offset = KVM_EXEC_NOTIFICATION_COMPLETION_OFFSET;
	header->command_entries = KVM_EXEC_NOTIFICATION_RING_ENTRIES;
	header->completion_entries = KVM_EXEC_NOTIFICATION_RING_ENTRIES;
	header->command_entry_size =
		sizeof(struct kvm_exec_notification_command);
	header->completion_entry_size =
		sizeof(struct kvm_exec_notification_completion);
}

static bool
kvm_exec_notification_header_valid(struct kvm_exec_notification_runner *runner)
{
	struct kvm_exec_notification_header *header =
		kvm_exec_notification_header(runner);

	return READ_ONCE(header->abi_version) ==
			KVM_EXEC_NOTIFICATION_ABI_VERSION &&
	       READ_ONCE(header->region_size) ==
			KVM_EXEC_NOTIFICATION_MMAP_SIZE &&
	       READ_ONCE(header->command_offset) ==
			KVM_EXEC_NOTIFICATION_COMMAND_OFFSET &&
	       READ_ONCE(header->completion_offset) ==
			KVM_EXEC_NOTIFICATION_COMPLETION_OFFSET &&
	       READ_ONCE(header->command_entries) ==
			KVM_EXEC_NOTIFICATION_RING_ENTRIES &&
	       READ_ONCE(header->completion_entries) ==
			KVM_EXEC_NOTIFICATION_RING_ENTRIES &&
	       READ_ONCE(header->command_entry_size) ==
			sizeof(struct kvm_exec_notification_command) &&
	       READ_ONCE(header->completion_entry_size) ==
			sizeof(struct kvm_exec_notification_completion) &&
	       !memchr_inv(header->reserved, 0, sizeof(header->reserved));
}

static u32 kvm_exec_notification_current_cpu(void)
{
	u32 cpu = get_cpu();

	put_cpu();
	return cpu;
}

static void kvm_exec_notification_update_hwm(struct kvm_exec_notification_runner *runner,
					     u64 occupancy)
{
	s64 desired = occupancy;
	s64 observed = atomic64_read(&runner->high_watermark);

	while (desired > observed &&
	       !atomic64_try_cmpxchg(&runner->high_watermark, &observed,
				     desired))
		cpu_relax();
}

static struct kvm_exec_executor *
kvm_exec_find_executor(struct kvm_exec_domain *domain, u64 generation,
		       u64 cookie)
{
	struct kvm_exec_executor *executor;

	mutex_lock(&domain->lock);
	list_for_each_entry(executor, &domain->executors, node) {
		if (executor->generation == generation &&
		    executor->cookie == cookie && executor->listed) {
			kref_get(&executor->kref);
			mutex_unlock(&domain->lock);
			return executor;
		}
	}
	mutex_unlock(&domain->lock);
	return NULL;
}

static u32 kvm_exec_notification_status(int ret)
{
	switch (ret) {
	case 0:
		return KVM_EXEC_NOTIFICATION_COMPLETE_DELIVERED;
	case -EAGAIN:
		return KVM_EXEC_NOTIFICATION_COMPLETE_RETRY;
	case -ESTALE:
	case -ENOENT:
		return KVM_EXEC_NOTIFICATION_COMPLETE_STALE;
	case -EBUSY:
		return KVM_EXEC_NOTIFICATION_COMPLETE_BUSY;
	case -EOPNOTSUPP:
		return KVM_EXEC_NOTIFICATION_COMPLETE_UNSUPPORTED;
	case -ESHUTDOWN:
		return KVM_EXEC_NOTIFICATION_COMPLETE_STOPPED;
	default:
		return KVM_EXEC_NOTIFICATION_COMPLETE_MALFORMED;
	}
}

static bool kvm_exec_notification_command_valid(struct kvm_exec_notification_runner *runner,
						const struct kvm_exec_notification_command *command)
{
	return command->size == sizeof(*command) &&
	       !(command->flags & ~KVM_EXEC_INTERRUPT_F_RETAIN_HLT) &&
	       command->domain_generation == runner->domain->generation &&
	       command->runner_generation == runner->generation &&
	       command->executor_generation && command->request_sequence &&
	       command->capsule_id && command->lifecycle_generation &&
	       command->vector <= U8_MAX &&
	       command->requested_delivery ==
			READ_ONCE(runner->domain->interrupt_delivery) &&
	       !memchr_inv(command->reserved, 0, sizeof(command->reserved));
}

static int
kvm_exec_notification_process(struct kvm_exec_notification_runner *runner,
			      const struct kvm_exec_notification_command *command,
			      struct kvm_exec_notification_completion *completion,
			      bool stopped)
{
	struct kvm_exec_interrupt_request request;
	struct kvm_exec_executor *executor;
	unsigned long flags;
	u64 executor_generation;
	u64 executor_cookie;
	int ret;

	completion->size = sizeof(*completion);
	completion->domain_generation = runner->domain->generation;
	completion->runner_generation = runner->generation;
	completion->executor_generation = command->executor_generation;
	completion->request_sequence = command->request_sequence;
	completion->correlation_cookie = command->correlation_cookie;
	completion->consumed_ns = ktime_get_ns();

	if (stopped) {
		ret = -ESHUTDOWN;
		goto complete;
	}
	if (!kvm_exec_notification_command_valid(runner, command)) {
		ret = -EINVAL;
		goto complete;
	}

	executor_generation = command->executor_generation;
	executor_cookie = command->executor_cookie;
	executor = kvm_exec_find_executor(runner->domain, executor_generation,
					  executor_cookie);
	if (!executor) {
		ret = -ESTALE;
		goto complete;
	}

	request = (struct kvm_exec_interrupt_request) {
		.domain_generation = command->domain_generation,
		.executor_generation = command->executor_generation,
		.request_sequence = command->request_sequence,
		.capsule_id = command->capsule_id,
		.lifecycle_generation = command->lifecycle_generation,
		.correlation_cookie = command->correlation_cookie,
		.vector = command->vector,
		.flags = command->flags,
		.requested_delivery = command->requested_delivery,
	};
	ret = kvm_exec_submit_interrupt(executor, &request);
	if (!ret) {
		spin_lock_irqsave(&executor->interrupt_lock, flags);
		completion->actual_delivery = executor->last_interrupt_delivery;
		completion->accepted_tsc =
			executor->last_interrupt_accepted_tsc;
		completion->delivered_tsc =
			executor->last_interrupt_delivered_tsc;
		spin_unlock_irqrestore(&executor->interrupt_lock, flags);
	}
	kref_put(&executor->kref, kvm_exec_executor_free);

complete:
	completion->result = ret;
	completion->status = kvm_exec_notification_status(ret);
	return ret;
}

static void kvm_exec_notification_publish(struct kvm_exec_notification_runner *runner,
					  const struct kvm_exec_notification_completion *completion,
					  u64 completion_tail)
{
	struct kvm_exec_notification_header *header =
		kvm_exec_notification_header(runner);
	struct kvm_exec_notification_completion *entries =
		kvm_exec_notification_completions(runner);

	entries[completion_tail &
		(KVM_EXEC_NOTIFICATION_RING_ENTRIES - 1)] = *completion;
	/* Publish the complete payload before userspace observes the new tail. */
	smp_store_release(&header->completion_tail, completion_tail + 1);
	WRITE_ONCE(header->last_completed_ns, ktime_get_ns());
}

static long
kvm_exec_run_notification(struct kvm_exec_notification_runner *runner,
			  void __user *argp)
{
	struct kvm_exec_notification_header *header =
		kvm_exec_notification_header(runner);
	struct kvm_exec_notification_command *commands =
		kvm_exec_notification_commands(runner);
	const struct kvm_exec_notification_command *command;
	struct kvm_exec_notification_completion completion;
	struct kvm_exec_run_notification run;
	unsigned long flags;
	u64 command_head, command_tail, completion_head, completion_tail;
	u64 command_occupancy, completion_occupancy;
	u64 iterations = 0;
	u64 heartbeat, return_count;
	u32 return_reason = 0;
	bool force_stop = false;
	int fatal_error = 0;
	int ret;

	ret = kvm_exec_domain_access(runner->domain);
	if (ret)
		return ret;
	if (copy_from_user(&run, argp, sizeof(run)))
		return -EFAULT;
	if (run.size != sizeof(run) || run.flags ||
	    run.domain_generation != runner->domain->generation ||
	    run.runner_generation != runner->generation || run.return_reason ||
	    run.run_result || run.current_cpu || run.reserved0 ||
	    run.consumed_count || run.completed_count ||
	    memchr_inv(run.reserved, 0, sizeof(run.reserved)))
		return -EINVAL;
	if (mutex_lock_killable(&runner->run_lock))
		return -EINTR;

	spin_lock_irqsave(&runner->state_lock, flags);
	if (runner->state != KVM_EXEC_NOTIFICATION_STATE_CREATED ||
	    runner->running) {
		spin_unlock_irqrestore(&runner->state_lock, flags);
		ret = -EBUSY;
		goto out_unlock;
	}
	atomic_set(&runner->observed_cpu,
		   kvm_exec_notification_current_cpu());
	if (atomic_read(&runner->observed_cpu) != runner->requested_cpu) {
		runner->state = KVM_EXEC_NOTIFICATION_STATE_FATAL;
		runner->last_error = -EXDEV;
		spin_unlock_irqrestore(&runner->state_lock, flags);
		ret = -EXDEV;
		goto out_unlock;
	}
	runner->state = KVM_EXEC_NOTIFICATION_STATE_RUNNING;
	runner->runner_tid = task_pid_nr(current);
	runner->running = true;
	spin_unlock_irqrestore(&runner->state_lock, flags);

	for (;;) {
		bool drain_requested, stop_requested;
		u32 cpu;

		if (unlikely(READ_ONCE(runner->domain->stopping))) {
			force_stop = true;
			return_reason =
				KVM_EXEC_NOTIFICATION_RETURN_DOMAIN_STOPPING;
		}
		if (unlikely(signal_pending(current))) {
			force_stop = true;
			return_reason = KVM_EXEC_NOTIFICATION_RETURN_SIGNAL;
		}
		cpu = kvm_exec_notification_current_cpu();
		if (unlikely(cpu != runner->requested_cpu)) {
			force_stop = true;
			return_reason =
				KVM_EXEC_NOTIFICATION_RETURN_CPU_MIGRATED;
			fatal_error = -EXDEV;
		}
		atomic_set(&runner->observed_cpu, cpu);

		spin_lock_irqsave(&runner->state_lock, flags);
		drain_requested = runner->drain_requested;
		stop_requested = runner->stop_requested;
		if (stop_requested)
			force_stop = true;
		spin_unlock_irqrestore(&runner->state_lock, flags);
		if (stop_requested && !return_reason)
			return_reason = KVM_EXEC_NOTIFICATION_RETURN_STOPPED;

		if (unlikely(!kvm_exec_notification_header_valid(runner))) {
			return_reason = KVM_EXEC_NOTIFICATION_RETURN_CORRUPT;
			fatal_error = -EPROTO;
			break;
		}

		command_head = READ_ONCE(header->command_head);
		/* Acquire the producer tail before reading its command payload. */
		command_tail = smp_load_acquire(&header->command_tail);
		/* Acquire userspace's release before reusing a completion slot. */
		completion_head = smp_load_acquire(&header->completion_head);
		completion_tail = READ_ONCE(header->completion_tail);
		command_occupancy = command_tail - command_head;
		completion_occupancy = completion_tail - completion_head;
		if (unlikely(command_occupancy >
			     KVM_EXEC_NOTIFICATION_RING_ENTRIES ||
		     completion_occupancy >
			     KVM_EXEC_NOTIFICATION_RING_ENTRIES)) {
			return_reason = KVM_EXEC_NOTIFICATION_RETURN_CORRUPT;
			fatal_error = -EPROTO;
			break;
		}
		kvm_exec_notification_update_hwm(runner, command_occupancy);

		if (!command_occupancy) {
			if (force_stop || drain_requested) {
				if (!return_reason)
					return_reason =
						KVM_EXEC_NOTIFICATION_RETURN_DRAINED;
				break;
			}
			cpu_relax();
			goto heartbeat;
		}
		if (completion_occupancy ==
		    KVM_EXEC_NOTIFICATION_RING_ENTRIES) {
			if (!runner->full_observed) {
				atomic64_inc(&runner->full_count);
				runner->full_observed = true;
			}
			/*
			 * A producer that stops consuming completions must not be
			 * able to pin domain teardown indefinitely.  Commands still
			 * in the ring were never accepted, so fail the runner instead
			 * of waiting for completion space that cannot be guaranteed.
			 */
			if (force_stop) {
				fatal_error = -ENOSPC;
				break;
			}
			cpu_relax();
			goto heartbeat;
		}
		runner->full_observed = false;

		memset(&completion, 0, sizeof(completion));
		command = &commands[command_head &
			(KVM_EXEC_NOTIFICATION_RING_ENTRIES - 1)];
		kvm_exec_notification_process(runner, command, &completion,
					      force_stop);
		/* Release the command slot only after its payload is consumed. */
		smp_store_release(&header->command_head, command_head + 1);
		WRITE_ONCE(header->last_consumed_ns, completion.consumed_ns);
		atomic64_inc(&runner->consumed_count);
		if (completion.status ==
		    KVM_EXEC_NOTIFICATION_COMPLETE_MALFORMED)
			atomic64_inc(&runner->malformed_count);
		if (completion.status == KVM_EXEC_NOTIFICATION_COMPLETE_STALE)
			atomic64_inc(&runner->stale_count);
		kvm_exec_notification_publish(runner, &completion,
					      completion_tail);
		atomic64_inc(&runner->completed_count);

heartbeat:
		heartbeat = atomic64_inc_return(&runner->heartbeat);
		if (!(heartbeat & 0xff))
			WRITE_ONCE(header->heartbeat, heartbeat);
		if (!(++iterations & 0xfff))
			cond_resched();
	}

	spin_lock_irqsave(&runner->state_lock, flags);
	runner->running = false;
	runner->last_error = fatal_error;
	runner->state = runner->last_error ?
		KVM_EXEC_NOTIFICATION_STATE_FATAL :
		KVM_EXEC_NOTIFICATION_STATE_STOPPED;
	run.current_cpu = atomic_read(&runner->observed_cpu);
	run.consumed_count = atomic64_read(&runner->consumed_count);
	run.completed_count = atomic64_read(&runner->completed_count);
	spin_unlock_irqrestore(&runner->state_lock, flags);
	return_count = atomic64_inc_return(&runner->return_count);
	run.return_reason = return_reason;
	run.run_result = fatal_error;
	WRITE_ONCE(header->heartbeat, atomic64_read(&runner->heartbeat));
	WRITE_ONCE(header->kernel_return_count, return_count);
	wake_up_all(&runner->wait);
	ret = copy_to_user(argp, &run, sizeof(run)) ? -EFAULT : 0;

out_unlock:
	mutex_unlock(&runner->run_lock);
	return ret;
}

static bool kvm_exec_notification_control_valid(struct kvm_exec_notification_runner *runner,
						const struct kvm_exec_notification_control *control)
{
	return control->size == sizeof(*control) && !control->flags &&
	       control->domain_generation == runner->domain->generation &&
	       control->runner_generation == runner->generation &&
	       !memchr_inv(control->reserved, 0, sizeof(control->reserved));
}

static long
kvm_exec_notification_control(struct kvm_exec_notification_runner *runner,
			      void __user *argp, bool stop)
{
	struct kvm_exec_notification_control control;
	unsigned long flags;
	int ret;

	ret = kvm_exec_domain_access(runner->domain);
	if (ret)
		return ret;
	if (copy_from_user(&control, argp, sizeof(control)))
		return -EFAULT;
	if (!kvm_exec_notification_control_valid(runner, &control))
		return -EINVAL;

	spin_lock_irqsave(&runner->state_lock, flags);
	if (!runner->running) {
		ret = -EALREADY;
	} else {
		runner->drain_requested = true;
		runner->stop_requested |= stop;
		runner->state = KVM_EXEC_NOTIFICATION_STATE_DRAINING;
		ret = 0;
	}
	spin_unlock_irqrestore(&runner->state_lock, flags);
	return ret;
}

static long
kvm_exec_query_notification(struct kvm_exec_notification_runner *runner,
			    void __user *argp)
{
	struct kvm_exec_notification_header *header =
		kvm_exec_notification_header(runner);
	struct kvm_exec_query_notification_runner query;
	unsigned long flags;
	u64 command_head, command_tail, completion_head, completion_tail;
	int ret;

	ret = kvm_exec_domain_access(runner->domain);
	if (ret)
		return ret;
	if (copy_from_user(&query, argp, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.flags ||
	    query.domain_generation != runner->domain->generation ||
	    query.runner_generation != runner->generation ||
	    query.runner_cookie || query.requested_cpu || query.observed_cpu ||
	    query.state || query.last_error || query.runner_tid ||
	    query.heartbeat || query.consumed_count || query.completed_count ||
	    query.full_count || query.malformed_count || query.stale_count ||
	    query.high_watermark || query.command_occupancy ||
	    query.completion_occupancy || query.kernel_return_count ||
	    memchr_inv(query.reserved, 0, sizeof(query.reserved)))
		return -EINVAL;

	/* Pair with both producers before reporting a coherent occupancy. */
	command_head = smp_load_acquire(&header->command_head);
	/* Acquire the userspace command publication point. */
	command_tail = smp_load_acquire(&header->command_tail);
	/* Acquire the userspace completion-consumption point. */
	completion_head = smp_load_acquire(&header->completion_head);
	/* Acquire the kernel completion publication point. */
	completion_tail = smp_load_acquire(&header->completion_tail);
	spin_lock_irqsave(&runner->state_lock, flags);
	query.runner_cookie = runner->cookie;
	query.requested_cpu = runner->requested_cpu;
	query.observed_cpu = atomic_read(&runner->observed_cpu);
	query.state = runner->state;
	query.last_error = runner->last_error;
	query.runner_tid = runner->runner_tid;
	query.heartbeat = atomic64_read(&runner->heartbeat);
	query.consumed_count = atomic64_read(&runner->consumed_count);
	query.completed_count = atomic64_read(&runner->completed_count);
	query.full_count = atomic64_read(&runner->full_count);
	query.malformed_count = atomic64_read(&runner->malformed_count);
	query.stale_count = atomic64_read(&runner->stale_count);
	query.high_watermark = atomic64_read(&runner->high_watermark);
	query.kernel_return_count = atomic64_read(&runner->return_count);
	spin_unlock_irqrestore(&runner->state_lock, flags);
	query.command_occupancy = command_tail - command_head;
	query.completion_occupancy = completion_tail - completion_head;
	memset(query.reserved, 0, sizeof(query.reserved));

	return copy_to_user(argp, &query, sizeof(query)) ? -EFAULT : 0;
}

static void
kvm_exec_notification_request_stop(struct kvm_exec_notification_runner *runner)
{
	unsigned long flags;

	spin_lock_irqsave(&runner->state_lock, flags);
	runner->drain_requested = true;
	runner->stop_requested = true;
	if (runner->running)
		runner->state = KVM_EXEC_NOTIFICATION_STATE_DRAINING;
	spin_unlock_irqrestore(&runner->state_lock, flags);
}

static void kvm_exec_notification_free(struct kref *kref)
{
	struct kvm_exec_notification_runner *runner =
		container_of(kref, struct kvm_exec_notification_runner, kref);

	if (runner->region)
		free_pages_exact(runner->region,
				 KVM_EXEC_NOTIFICATION_MMAP_SIZE);
	kref_put(&runner->domain->kref, kvm_exec_domain_free);
	kfree(runner);
}

static int kvm_exec_notification_flush(struct file *file, fl_owner_t id)
{
	struct kvm_exec_notification_runner *runner = file->private_data;

	/* A forked, wrong-mm descriptor must not stop the owning runner. */
	if (!kvm_exec_domain_access(runner->domain))
		kvm_exec_notification_request_stop(runner);
	return 0;
}

static int kvm_exec_notification_release(struct inode *inode, struct file *file)
{
	struct kvm_exec_notification_runner *runner = file->private_data;
	struct kvm_exec_domain *domain = runner->domain;

	kvm_exec_notification_request_stop(runner);
	wait_event(runner->wait, !READ_ONCE(runner->running));
	mutex_lock(&domain->lock);
	if (runner->listed) {
		WARN_ON_ONCE(domain->notification_runner != runner);
		domain->notification_runner = NULL;
		runner->listed = false;
	}
	mutex_unlock(&domain->lock);
	kref_put(&runner->kref, kvm_exec_notification_free);
	return 0;
}

static long kvm_exec_notification_ioctl(struct file *file,
					unsigned int ioctl, unsigned long arg)
{
	struct kvm_exec_notification_runner *runner = file->private_data;
	void __user *argp = (void __user *)arg;

	if (_IOC_TYPE(ioctl) != KVMIO)
		return -EINVAL;
	switch (ioctl) {
	case KVM_EXEC_RUN_NOTIFICATION:
		return kvm_exec_run_notification(runner, argp);
	case KVM_EXEC_DRAIN_NOTIFICATION:
		return kvm_exec_notification_control(runner, argp, false);
	case KVM_EXEC_STOP_NOTIFICATION:
		return kvm_exec_notification_control(runner, argp, true);
	case KVM_EXEC_QUERY_NOTIFICATION_RUNNER:
		return kvm_exec_query_notification(runner, argp);
	default:
		return -ENOTTY;
	}
}

static void kvm_exec_notification_vma_open(struct vm_area_struct *vma)
{
	struct kvm_exec_notification_runner *runner = vma->vm_private_data;

	kref_get(&runner->kref);
}

static void kvm_exec_notification_vma_close(struct vm_area_struct *vma)
{
	struct kvm_exec_notification_runner *runner = vma->vm_private_data;

	kref_put(&runner->kref, kvm_exec_notification_free);
}

static const struct vm_operations_struct kvm_exec_notification_vm_ops = {
	.open = kvm_exec_notification_vma_open,
	.close = kvm_exec_notification_vma_close,
};

static int kvm_exec_notification_mmap(struct file *file,
				      struct vm_area_struct *vma)
{
	struct kvm_exec_notification_runner *runner = file->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn;
	int ret;

	ret = kvm_exec_domain_access(runner->domain);
	if (ret)
		return ret;
	if (vma->vm_pgoff || size != KVM_EXEC_NOTIFICATION_MMAP_SIZE ||
	    !(vma->vm_flags & VM_SHARED) || (vma->vm_flags & VM_EXEC))
		return -EINVAL;

	pfn = page_to_pfn(virt_to_page(runner->region));
	vm_flags_set(vma, VM_DONTCOPY | VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_ops = &kvm_exec_notification_vm_ops;
	vma->vm_private_data = runner;
	kvm_exec_notification_vma_open(vma);
	ret = remap_pfn_range(vma, vma->vm_start, pfn, size,
			      vma->vm_page_prot);
	if (ret)
		kvm_exec_notification_vma_close(vma);
	return ret;
}

static const struct file_operations kvm_exec_notification_fops = {
	.owner = THIS_MODULE,
	.flush = kvm_exec_notification_flush,
	.release = kvm_exec_notification_release,
	.unlocked_ioctl = kvm_exec_notification_ioctl,
	.mmap = kvm_exec_notification_mmap,
	.llseek = noop_llseek,
#ifdef CONFIG_COMPAT
	.compat_ioctl = kvm_exec_notification_ioctl,
#endif
};

static long
kvm_exec_create_notification_runner(struct kvm_exec_domain *domain,
				    void __user *argp)
{
	struct kvm_exec_create_notification_runner create;
	struct kvm_exec_notification_runner *runner;
	struct file *file;
	int fd, ret;

	if (!(domain->negotiated_features &
	      KVM_EXEC_FEATURE_NOTIFICATION_RING))
		return -EOPNOTSUPP;
	if (copy_from_user(&create, argp, sizeof(create)))
		return -EFAULT;
	if (create.size != sizeof(create) ||
	    create.flags != KVM_EXEC_NOTIFICATION_F_STRICT_CPU ||
	    create.domain_generation != domain->generation ||
	    create.requested_cpu >= nr_cpu_ids ||
	    !cpu_possible(create.requested_cpu) || create.reserved0 ||
	    create.runner_generation ||
	    memchr_inv(create.reserved, 0, sizeof(create.reserved)))
		return -EINVAL;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;
	runner = kzalloc(sizeof(*runner), GFP_KERNEL_ACCOUNT);
	if (!runner) {
		put_unused_fd(fd);
		return -ENOMEM;
	}
	runner->region = alloc_pages_exact(KVM_EXEC_NOTIFICATION_MMAP_SIZE,
					   GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!runner->region) {
		kfree(runner);
		put_unused_fd(fd);
		return -ENOMEM;
	}

	runner->domain = domain;
	runner->generation =
		kvm_exec_next_generation(&kvm_exec_notification_generation);
	runner->cookie = create.runner_cookie;
	runner->requested_cpu = create.requested_cpu;
	atomic_set(&runner->observed_cpu, KVM_EXEC_CPU_ANY);
	runner->state = KVM_EXEC_NOTIFICATION_STATE_CREATED;
	kref_init(&runner->kref);
	mutex_init(&runner->run_lock);
	spin_lock_init(&runner->state_lock);
	init_waitqueue_head(&runner->wait);
	atomic64_set(&runner->heartbeat, 0);
	atomic64_set(&runner->consumed_count, 0);
	atomic64_set(&runner->completed_count, 0);
	atomic64_set(&runner->full_count, 0);
	atomic64_set(&runner->malformed_count, 0);
	atomic64_set(&runner->stale_count, 0);
	atomic64_set(&runner->high_watermark, 0);
	atomic64_set(&runner->return_count, 0);
	kvm_exec_notification_region_init(runner);
	kref_get(&domain->kref);
	file = anon_inode_getfile("kvm-exec-notification",
				  &kvm_exec_notification_fops, runner, O_RDWR);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		kref_put(&runner->kref, kvm_exec_notification_free);
		put_unused_fd(fd);
		return ret;
	}

	mutex_lock(&domain->lock);
	if (domain->stopping) {
		ret = -ESHUTDOWN;
	} else if (domain->notification_runner) {
		ret = -EBUSY;
	} else {
		domain->notification_runner = runner;
		runner->listed = true;
		ret = 0;
	}
	mutex_unlock(&domain->lock);
	if (ret)
		goto out_file;

	create.runner_generation = runner->generation;
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

static long kvm_exec_interrupt(struct kvm_exec_executor *executor,
			       void __user *argp)
{
	struct kvm_exec_interrupt interrupt;
	struct kvm_exec_interrupt_request request;

	if (copy_from_user(&interrupt, argp, sizeof(interrupt)))
		return -EFAULT;
	if (interrupt.size != sizeof(interrupt) ||
	    interrupt.flags & ~KVM_EXEC_INTERRUPT_F_RETAIN_HLT ||
	    !interrupt.request_sequence || interrupt.vector > U8_MAX ||
	    interrupt.reserved0 ||
	    memchr_inv(interrupt.reserved, 0, sizeof(interrupt.reserved)))
		return -EINVAL;

	request = (struct kvm_exec_interrupt_request) {
		.domain_generation = interrupt.domain_generation,
		.executor_generation = interrupt.executor_generation,
		.request_sequence = interrupt.request_sequence,
		.capsule_id = interrupt.capsule_id,
		.lifecycle_generation = interrupt.lifecycle_generation,
		.vector = interrupt.vector,
		.flags = interrupt.flags,
		.requested_delivery = READ_ONCE(executor->domain->interrupt_delivery),
	};
	return kvm_exec_submit_interrupt(executor, &request);
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

static long kvm_exec_query_executor(struct kvm_exec_executor *executor,
				    void __user *argp)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_query_executor query;
	struct kvm_exec_capsule *capsule;
	unsigned long flags;
	u32 block_reason;
	int ret;

	ret = kvm_exec_domain_access(domain);
	if (ret)
		return ret;
	if (!(domain->negotiated_features & KVM_EXEC_FEATURE_LIFECYCLE_STATE))
		return -EOPNOTSUPP;
	if (copy_from_user(&query, argp, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.flags ||
	    query.interrupt_queued_count || query.interrupt_applied_count ||
	    query.last_interrupt_sequence || query.pending_interrupt_sequence)
		return -EINVAL;
	if (query.domain_generation != domain->generation ||
	    query.executor_generation != executor->generation)
		return -ESTALE;

	mutex_lock(&domain->lock);
	query.executor_cookie = executor->cookie;
	query.state = KVM_EXEC_EXECUTOR_STATE_IDLE;
	query.current_cpu = atomic_read(&executor->last_cpu);
	query.current_capsule_id = 0;
	query.current_lifecycle_generation = 0;
	capsule = executor->current_capsule;
	if (capsule) {
		query.current_capsule_id = capsule->capsule_id;
		query.current_lifecycle_generation =
			capsule->lifecycle_generation;
	}
	if (domain->stopping) {
		query.state = KVM_EXEC_EXECUTOR_STATE_STOPPING;
	} else if (domain->paused) {
		query.state = KVM_EXEC_EXECUTOR_STATE_PAUSED;
	} else if (capsule) {
		block_reason = atomic_read(&capsule->block_reason);
		if (capsule->exit.completion_pending)
			query.state =
				KVM_EXEC_EXECUTOR_STATE_COMPLETION_PENDING;
		else if (capsule->running)
			query.state = KVM_EXEC_EXECUTOR_STATE_RUNNING;
		else if (block_reason == KVM_EXEC_BLOCK_HLT)
			query.state = KVM_EXEC_EXECUTOR_STATE_BLOCKED_HLT;
		else if (block_reason == KVM_EXEC_BLOCK_VMM_EXIT)
			query.state = KVM_EXEC_EXECUTOR_STATE_BLOCKED_VMM;
	}
	query.run_count = atomic64_read(&executor->run_count);
	query.switch_count = atomic64_read(&executor->switch_count);
	query.release_count = atomic64_read(&executor->release_count);
	query.rejected_count = atomic64_read(&executor->rejected_count);
	query.cancelled_count = atomic64_read(&executor->cancelled_count);
	query.exit_count = atomic64_read(&executor->exit_count);
	query.failure_count = atomic64_read(&executor->failure_count);
	query.runtime_ns = atomic64_read(&executor->runtime_ns);
	spin_lock_irqsave(&executor->interrupt_lock, flags);
	query.interrupt_queued_count = executor->interrupt_queued_count;
	query.interrupt_applied_count = executor->interrupt_applied_count;
	query.last_interrupt_sequence = executor->last_interrupt_sequence;
	query.pending_interrupt_sequence =
		executor->pending_interrupt_sequence;
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);
	mutex_unlock(&domain->lock);

	return copy_to_user(argp, &query, sizeof(query)) ? -EFAULT : 0;
}

static long
kvm_exec_query_interrupt_publication(struct kvm_exec_executor *executor,
				     void __user *argp)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_query_interrupt_publication query;
	unsigned long flags;
	int ret;

	ret = kvm_exec_domain_access(domain);
	if (ret)
		return ret;
	if (!(domain->negotiated_features &
	      KVM_EXEC_FEATURE_INTERRUPT_PUBLICATION))
		return -EOPNOTSUPP;
	if (copy_from_user(&query, argp, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.flags ||
	    query.accepted_count || query.delivered_count ||
	    query.last_request_sequence || query.accepted_ns ||
	    query.delivered_ns || query.actual_delivery || query.reserved0 ||
	    query.accepted_tsc || query.delivered_tsc ||
	    memchr_inv(query.reserved, 0, sizeof(query.reserved)))
		return -EINVAL;
	if (query.domain_generation != domain->generation ||
	    query.executor_generation != executor->generation)
		return -ESTALE;

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	query.accepted_count = executor->interrupt_queued_count;
	query.delivered_count = executor->interrupt_delivery_count;
	query.last_request_sequence = executor->last_interrupt_sequence;
	query.accepted_ns = executor->last_interrupt_accepted_ns;
	query.delivered_ns = executor->last_interrupt_delivered_ns;
	query.accepted_tsc = executor->last_interrupt_accepted_tsc;
	query.delivered_tsc = executor->last_interrupt_delivered_tsc;
	query.actual_delivery = executor->last_interrupt_delivery;
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);

	return copy_to_user(argp, &query, sizeof(query)) ? -EFAULT : 0;
}

static long
kvm_exec_query_interrupt_delivery(struct kvm_exec_executor *executor,
				  void __user *argp)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_query_interrupt_delivery query;
	unsigned long flags;
	int ret;

	ret = kvm_exec_domain_access(domain);
	if (ret)
		return ret;
	if (!(domain->negotiated_features &
	      KVM_EXEC_FEATURE_INTERRUPT_PUBLICATION))
		return -EOPNOTSUPP;
	if (copy_from_user(&query, argp, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.flags ||
	    query.domain_generation != domain->generation ||
	    query.executor_generation != executor->generation ||
	    query.configured_delivery || query.apicv_inhibited ||
	    query.vector_queued_count || query.forced_kick_count ||
	    query.handler_delivery_count || query.eoi_count ||
	    query.coalesced_count || query.rejection_count ||
	    query.pending_sequence ||
	    memchr_inv(query.reserved, 0, sizeof(query.reserved)))
		return -EINVAL;

	spin_lock_irqsave(&executor->interrupt_lock, flags);
	query.configured_delivery = domain->interrupt_delivery;
	query.apicv_inhibited =
		domain->interrupt_delivery ==
		KVM_EXEC_INTERRUPT_DELIVERY_LOCAL_APIC_KICK &&
		READ_ONCE(domain->nr_attached);
	query.vector_queued_count = executor->interrupt_vector_queued_count;
	query.forced_kick_count = executor->interrupt_forced_kick_count;
	query.handler_delivery_count =
		executor->interrupt_handler_delivery_count;
	query.eoi_count = executor->interrupt_eoi_count;
	query.coalesced_count = executor->interrupt_coalesced_count;
	query.rejection_count = executor->interrupt_rejection_count;
	query.pending_sequence = executor->pending_interrupt_sequence;
	memset(query.reserved, 0, sizeof(query.reserved));
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);

	return copy_to_user(argp, &query, sizeof(query)) ? -EFAULT : 0;
}

static long
kvm_exec_query_posted_interrupt(struct kvm_exec_executor *executor,
				void __user *argp)
{
	struct kvm_exec_domain *domain = executor->domain;
	struct kvm_exec_query_posted_interrupt query;
	struct kvm_exec_capsule *capsule;
	unsigned long flags;
	int ret;

	ret = kvm_exec_domain_access(domain);
	if (ret)
		return ret;
	if (!(domain->negotiated_features &
	      KVM_EXEC_FEATURE_POSTED_INTERRUPT_DELIVERY))
		return -EOPNOTSUPP;
	if (copy_from_user(&query, argp, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.flags ||
	    query.domain_generation != domain->generation ||
	    query.executor_generation != executor->generation ||
	    query.posted_count || query.notification_coalesced_count ||
	    query.root_mode_rejection_count ||
	    query.inactive_rejection_count || query.stale_rejection_count ||
	    query.disarmed_count || query.superseded_count ||
	    query.target_notification_exit_count || query.pending_sequence ||
	    query.last_notification_cpu || query.last_delivery_tsc ||
	    query.apicv_active || query.strict_mode ||
	    memchr_inv(query.reserved, 0, sizeof(query.reserved)))
		return -EINVAL;

	mutex_lock(&domain->lock);
	spin_lock_irqsave(&executor->interrupt_lock, flags);
	query.posted_count = executor->interrupt_posted_count;
	query.notification_coalesced_count =
		executor->interrupt_posted_coalesced_count;
	query.root_mode_rejection_count =
		executor->interrupt_posted_root_rejection_count;
	query.inactive_rejection_count =
		executor->interrupt_posted_inactive_rejection_count;
	query.stale_rejection_count =
		executor->interrupt_posted_stale_rejection_count;
	query.disarmed_count = executor->interrupt_posted_disarmed_count;
	query.superseded_count = executor->interrupt_posted_superseded_count;
	query.target_notification_exit_count =
		executor->interrupt_posted_target_exit_count;
	if (executor->pending_interrupt_delivery ==
	    KVM_EXEC_INTERRUPT_DELIVERY_POSTED)
		query.target_notification_exit_count +=
			(u32)kvm_arch_exec_posted_notification_exits(
				executor->last_interrupt_notification_cpu) -
			(u32)executor->interrupt_posted_target_exit_baseline;
	query.pending_sequence = executor->pending_interrupt_sequence;
	query.last_notification_cpu =
		executor->last_interrupt_notification_cpu;
	query.last_delivery_tsc = executor->last_interrupt_delivered_tsc;
	query.strict_mode = domain->interrupt_delivery ==
		KVM_EXEC_INTERRUPT_DELIVERY_POSTED;
	capsule = executor->current_capsule;
	query.apicv_active = capsule && capsule->vcpu &&
		kvm_arch_vcpu_exec_posted_interrupt_active(capsule->vcpu);
	memset(query.reserved, 0, sizeof(query.reserved));
	spin_unlock_irqrestore(&executor->interrupt_lock, flags);
	mutex_unlock(&domain->lock);

	return copy_to_user(argp, &query, sizeof(query)) ? -EFAULT : 0;
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
	if (ioctl == KVM_EXEC_INTERRUPT)
		return kvm_exec_interrupt(executor, (void __user *)arg);
	if (ioctl == KVM_EXEC_CANCEL)
		return kvm_exec_cancel(executor, (void __user *)arg);
	if (ioctl == KVM_EXEC_QUERY_EXECUTOR)
		return kvm_exec_query_executor(executor, (void __user *)arg);
	if (ioctl == KVM_EXEC_QUERY_INTERRUPT_PUBLICATION)
		return kvm_exec_query_interrupt_publication(
			executor, (void __user *)arg);
	if (ioctl == KVM_EXEC_QUERY_INTERRUPT_DELIVERY)
		return kvm_exec_query_interrupt_delivery(
			executor, (void __user *)arg);
	if (ioctl == KVM_EXEC_QUERY_POSTED_INTERRUPT)
		return kvm_exec_query_posted_interrupt(
			executor, (void __user *)arg);
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
	struct kvm_exec_notification_runner *runner = NULL;
	struct kvm_exec_capsule *capsule;
	struct file *vcpu_file;
	unsigned long index;

	mutex_lock(&domain->lock);
	domain->stopping = true;
	domain->paused = true;
	if (domain->notification_runner) {
		runner = domain->notification_runner;
		kref_get(&runner->kref);
	}
	kvm_exec_kick_running_locked(domain);
	mutex_unlock(&domain->lock);
	if (runner) {
		kvm_exec_notification_request_stop(runner);
		wait_event(runner->wait, !READ_ONCE(runner->running));
		kref_put(&runner->kref, kvm_exec_notification_free);
	}

	wait_event(domain->drain_wait, !atomic_read(&domain->active_runs));

	mutex_lock(&domain->lock);
	kvm_exec_release_ownership_locked(domain);
	xa_for_each(&domain->capsules, index, capsule) {
		if (!capsule->vcpu)
			continue;
		mutex_lock(&capsule->vcpu->mutex);
		if (kvm_exec_delivery_uses_local_apic(
			    domain->interrupt_delivery))
			kvm_arch_vcpu_exec_configure_interrupt_delivery(
				capsule->vcpu, domain->interrupt_delivery, false);
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

static long kvm_exec_configure_interrupt_delivery(
	struct kvm_exec_domain *domain, void __user *argp)
{
	struct kvm_exec_interrupt_delivery_config config;
	int ret = 0;

	if (copy_from_user(&config, argp, sizeof(config)))
		return -EFAULT;
	if (config.size != sizeof(config) || config.flags ||
	    config.reserved0 ||
	    memchr_inv(config.reserved, 0, sizeof(config.reserved)))
		return -EINVAL;
	if (config.domain_generation != domain->generation)
		return -ESTALE;
	if (config.delivery != KVM_EXEC_INTERRUPT_DELIVERY_DIRECT_KICK &&
	    config.delivery !=
		KVM_EXEC_INTERRUPT_DELIVERY_LOCAL_APIC_KICK &&
	    config.delivery != KVM_EXEC_INTERRUPT_DELIVERY_POSTED)
		return -EOPNOTSUPP;
	if (config.delivery ==
		KVM_EXEC_INTERRUPT_DELIVERY_LOCAL_APIC_KICK &&
	    !(domain->negotiated_features &
	      KVM_EXEC_FEATURE_LOCAL_APIC_DELIVERY))
		return -EOPNOTSUPP;
	if (config.delivery == KVM_EXEC_INTERRUPT_DELIVERY_POSTED &&
	    !(domain->negotiated_features &
	      KVM_EXEC_FEATURE_POSTED_INTERRUPT_DELIVERY))
		return -EOPNOTSUPP;

	mutex_lock(&domain->lock);
	if (domain->stopping) {
		ret = -ESHUTDOWN;
	} else if (domain->interrupt_delivery_configured ||
		   domain->nr_attached || domain->nr_executors ||
		   domain->notification_runner) {
		ret = -EBUSY;
	} else {
		domain->interrupt_delivery = config.delivery;
		domain->interrupt_delivery_configured = true;
	}
	mutex_unlock(&domain->lock);
	return ret;
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
	case KVM_EXEC_CONFIGURE_INTERRUPT_DELIVERY:
		return kvm_exec_configure_interrupt_delivery(domain, argp);
	case KVM_EXEC_ATTACH_VCPU:
		return kvm_exec_attach_vcpu(domain, argp);
	case KVM_EXEC_DETACH_VCPU:
		return kvm_exec_detach_vcpu(domain, argp);
	case KVM_EXEC_CREATE_EXECUTOR:
		return kvm_exec_create_executor(domain, argp);
	case KVM_EXEC_CREATE_NOTIFICATION_RUNNER:
		return kvm_exec_create_notification_runner(domain, argp);
	case KVM_EXEC_QUERY_CAPSULE:
		return kvm_exec_query_capsule(domain, argp);
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
	u64 supported_features;
	int fd;

	if (!IS_ENABLED(CONFIG_X86_64))
		return -EOPNOTSUPP;
	if (copy_from_user(&create, argp, sizeof(create)))
		return -EFAULT;
	supported_features = kvm_exec_supported_features();
	if (create.size != sizeof(create) || create.flags ||
	    !create.max_capsules || !create.max_executors ||
	    create.max_capsules > U16_MAX || create.max_executors > U16_MAX ||
	    !(create.requested_features & KVM_EXEC_FEATURE_BASE_OBJECTS) ||
	    create.requested_features & ~supported_features ||
	    ((create.requested_features & KVM_EXEC_FEATURE_CROSS_VM_CHAIN) &&
	     !(create.requested_features & KVM_EXEC_FEATURE_INTRA_VM_CHAIN)) ||
	    ((create.requested_features & KVM_EXEC_FEATURE_SYNC_EXITS) &&
	     !(create.requested_features & KVM_EXEC_FEATURE_DYNAMIC_DISPATCH)) ||
	    ((create.requested_features & KVM_EXEC_FEATURE_ASYNC_PIO_WRITE) &&
	     (create.requested_features &
	      (KVM_EXEC_FEATURE_DYNAMIC_DISPATCH |
	       KVM_EXEC_FEATURE_SYNC_EXITS)) !=
	     (KVM_EXEC_FEATURE_DYNAMIC_DISPATCH |
	      KVM_EXEC_FEATURE_SYNC_EXITS)) ||
	    ((create.requested_features & KVM_EXEC_FEATURE_RETURN_KICK) &&
	     !(create.requested_features & KVM_EXEC_FEATURE_DYNAMIC_DISPATCH)) ||
	    ((create.requested_features & KVM_EXEC_FEATURE_EXACT_INTERRUPT) &&
	     !(create.requested_features & KVM_EXEC_FEATURE_DYNAMIC_DISPATCH)) ||
	    ((create.requested_features &
	      KVM_EXEC_FEATURE_INTERRUPT_PUBLICATION) &&
	     !(create.requested_features & KVM_EXEC_FEATURE_EXACT_INTERRUPT)) ||
	    ((create.requested_features &
	      KVM_EXEC_FEATURE_LOCAL_APIC_DELIVERY) &&
	     (create.requested_features &
	      (KVM_EXEC_FEATURE_EXACT_INTERRUPT |
	       KVM_EXEC_FEATURE_INTERRUPT_PUBLICATION)) !=
	     (KVM_EXEC_FEATURE_EXACT_INTERRUPT |
	      KVM_EXEC_FEATURE_INTERRUPT_PUBLICATION)) ||
	    ((create.requested_features &
	      KVM_EXEC_FEATURE_POSTED_INTERRUPT_DELIVERY) &&
	     (create.requested_features &
	      (KVM_EXEC_FEATURE_LOCAL_APIC_DELIVERY |
	       KVM_EXEC_FEATURE_EXACT_INTERRUPT |
	       KVM_EXEC_FEATURE_INTERRUPT_PUBLICATION)) !=
	     (KVM_EXEC_FEATURE_LOCAL_APIC_DELIVERY |
	      KVM_EXEC_FEATURE_EXACT_INTERRUPT |
	      KVM_EXEC_FEATURE_INTERRUPT_PUBLICATION)) ||
	    ((create.requested_features &
	      KVM_EXEC_FEATURE_NOTIFICATION_RING) &&
	     (create.requested_features &
	      (KVM_EXEC_FEATURE_EXACT_INTERRUPT |
	       KVM_EXEC_FEATURE_INTERRUPT_PUBLICATION)) !=
	     (KVM_EXEC_FEATURE_EXACT_INTERRUPT |
	      KVM_EXEC_FEATURE_INTERRUPT_PUBLICATION)) ||
	    ((create.requested_features & KVM_EXEC_FEATURE_LIFECYCLE_STATE) &&
	     (create.requested_features &
	      (KVM_EXEC_FEATURE_DYNAMIC_DISPATCH |
	       KVM_EXEC_FEATURE_SYNC_EXITS)) !=
	     (KVM_EXEC_FEATURE_DYNAMIC_DISPATCH |
	      KVM_EXEC_FEATURE_SYNC_EXITS)) ||
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
	domain->interrupt_delivery =
		KVM_EXEC_INTERRUPT_DELIVERY_DIRECT_KICK;
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
