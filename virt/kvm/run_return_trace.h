/* SPDX-License-Identifier: GPL-2.0-only */
/* Diagnostic timestamps, never an execution or ownership input. */
#ifndef KVM_RUN_RETURN_TRACE_H
#define KVM_RUN_RETURN_TRACE_H

#ifdef CONFIG_X86
#include <asm/tsc.h>
#include <linux/seq_file.h>

#define KVM_RETURN_TRACE_CAPACITY 8192

struct kvm_return_trace_event {
	u64 sequence;
	u64 tsc;
	u32 tid;
	u32 vcpu_id;
	s32 result;
	u32 exit_reason;
};

struct kvm_return_trace_buffer {
	u64 count;
	struct kvm_return_trace_event events[KVM_RETURN_TRACE_CAPACITY];
};

static DEFINE_PER_CPU(struct kvm_return_trace_buffer *, kvm_return_trace_buffers);
static DEFINE_MUTEX(kvm_return_trace_lock);
static bool run_return_trace;
static bool kvm_return_trace_ready;

static int kvm_return_trace_set(const char *val, const struct kernel_param *kp)
{
	struct kvm_return_trace_buffer *buffer;
	bool enabled;
	int cpu, ret = kstrtobool(val, &enabled);

	if (ret)
		return ret;
	mutex_lock(&kvm_return_trace_lock);
	if (enabled && !kvm_return_trace_ready) {
		ret = -ENODEV;
		goto out;
	}
	if (enabled) {
		for_each_possible_cpu(cpu) {
			if (per_cpu(kvm_return_trace_buffers, cpu))
				continue;
			buffer = kvzalloc(sizeof(*buffer), GFP_KERNEL);
			if (!buffer) {
				ret = -ENOMEM;
				goto out;
			}
			per_cpu(kvm_return_trace_buffers, cpu) = buffer;
		}
	}
	/* Buffers stay allocated until module teardown, including after disable. */
	smp_store_release(&run_return_trace, enabled);
out:
	mutex_unlock(&kvm_return_trace_lock);
	return ret;
}

static const struct kernel_param_ops kvm_return_trace_ops = {
	.set = kvm_return_trace_set,
	.get = param_get_bool,
};
module_param_cb(run_return_trace, &kvm_return_trace_ops, &run_return_trace, 0600);
MODULE_PARM_DESC(run_return_trace, "Record ordinary KVM_RUN return TSCs (diagnostic, x86 only)");

static void kvm_trace_run_return(struct kvm_vcpu *vcpu, int result)
{
	struct kvm_return_trace_buffer *buffer;
	struct kvm_return_trace_event *event;
	u64 sequence, tsc;

	if (!smp_load_acquire(&run_return_trace))
		return;
	preempt_disable();
	tsc = rdtsc_ordered();
	buffer = this_cpu_read(kvm_return_trace_buffers);
	sequence = READ_ONCE(buffer->count) + 1;
	event = &buffer->events[(sequence - 1) % KVM_RETURN_TRACE_CAPACITY];
	WRITE_ONCE(buffer->count, sequence);
	WRITE_ONCE(event->sequence, 0);
	/* Prevent a reader accepting the old tag with partially replaced fields. */
	smp_wmb();
	WRITE_ONCE(event->tsc, tsc);
	WRITE_ONCE(event->tid, task_pid_nr(current));
	WRITE_ONCE(event->vcpu_id, vcpu->vcpu_id);
	WRITE_ONCE(event->result, result);
	WRITE_ONCE(event->exit_reason, vcpu->run->exit_reason);
	smp_store_release(&event->sequence, sequence);
	preempt_enable();
}

static int kvm_return_trace_show(struct seq_file *m, void *unused)
{
	int cpu;

	seq_printf(m, "schema 1 capacity %u\n", KVM_RETURN_TRACE_CAPACITY);
	mutex_lock(&kvm_return_trace_lock);
	for_each_possible_cpu(cpu) {
		struct kvm_return_trace_buffer *buffer = per_cpu(kvm_return_trace_buffers, cpu);
		u64 count, first, sequence;

		if (!buffer)
			continue;
		count = READ_ONCE(buffer->count);
		seq_printf(m, "cpu %d count %llu\n", cpu, count);
		first = count > KVM_RETURN_TRACE_CAPACITY ? count - KVM_RETURN_TRACE_CAPACITY : 0;
		for (sequence = first + 1; sequence <= count; sequence++) {
			struct kvm_return_trace_event *event =
				&buffer->events[(sequence - 1) % KVM_RETURN_TRACE_CAPACITY];
			struct kvm_return_trace_event copy;

			copy.sequence = smp_load_acquire(&event->sequence);
			copy.tsc = READ_ONCE(event->tsc);
			copy.tid = READ_ONCE(event->tid);
			copy.vcpu_id = READ_ONCE(event->vcpu_id);
			copy.result = READ_ONCE(event->result);
			copy.exit_reason = READ_ONCE(event->exit_reason);
			smp_rmb();
			if (copy.sequence != sequence || READ_ONCE(event->sequence) != sequence) {
				seq_printf(m, "incomplete %d %llu\n", cpu, sequence);
				continue;
			}
			seq_printf(m, "event %d %llu %llu %u %u %d %u\n", cpu,
				   sequence, copy.tsc, copy.tid, copy.vcpu_id,
				   copy.result, copy.exit_reason);
		}
	}
	mutex_unlock(&kvm_return_trace_lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(kvm_return_trace);

static void kvm_return_trace_init(struct dentry *root)
{
	debugfs_create_file("run_return_trace", 0400, root, NULL, &kvm_return_trace_fops);
	mutex_lock(&kvm_return_trace_lock);
	kvm_return_trace_ready = true;
	mutex_unlock(&kvm_return_trace_lock);
}

static void kvm_return_trace_destroy(void)
{
	int cpu;

	/* No vCPU runs remain; removal of debugfs precedes this call. The core
	 * module may outlive kvm_intel and its kvm_exit()/kvm_init() cycle.
	 */
	mutex_lock(&kvm_return_trace_lock);
	kvm_return_trace_ready = false;
	smp_store_release(&run_return_trace, false);
	for_each_possible_cpu(cpu) {
		kvfree(per_cpu(kvm_return_trace_buffers, cpu));
		per_cpu(kvm_return_trace_buffers, cpu) = NULL;
	}
	mutex_unlock(&kvm_return_trace_lock);
}
#else
static inline void kvm_trace_run_return(struct kvm_vcpu *vcpu, int result) {}
static inline void kvm_return_trace_init(struct dentry *root) {}
static inline void kvm_return_trace_destroy(void) {}
#endif
#endif
