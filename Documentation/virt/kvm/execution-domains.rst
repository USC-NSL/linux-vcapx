.. SPDX-License-Identifier: GPL-2.0

======================
KVM execution domains
======================

Status
======

The execution-domain API is an experimental x86-64 interface.  Userspace must
query ``KVM_CAP_VCPU_EXEC_DOMAIN``, request an explicit feature set, validate
the returned set and fail closed if a required feature is absent.  The API
does not provide scheduling policy: KVM executes only the capsule named by an
exact userspace command.

An execution domain lets one userspace task run different existing KVM vCPUs
through a persistent executor fd.  A *capsule* is an attached vCPU plus its
domain ownership and lifecycle identity; it is not a copied architectural
context.  All VMs, vCPUs, domains and executors in a domain must belong to one
trusted process and one ``mm``.

Object and access model
=======================

``KVM_CREATE_EXEC_DOMAIN`` is issued on ``/dev/kvm`` and returns a domain fd.
The caller supplies nonzero capsule and executor limits and a requested
feature mask containing ``KVM_EXEC_FEATURE_BASE_OBJECTS``.  Unknown features,
invalid feature dependencies, flags or nonzero reserved fields are rejected.
The returned domain generation identifies this domain instance.

The creating ``mm`` and credentials are retained for the domain lifetime.
Every domain and executor operation requires both to match the current task.
Passing an fd to another process, changing credentials or executing a new
image therefore does not grant access.  This restriction is deliberate: the
mapped rings and attached ``kvm_run`` pages are a single-process transport,
not an inter-process boundary.

``KVM_EXEC_ATTACH_VCPU`` attaches an existing vCPU fd under an opaque nonzero
capsule id and nonzero lifecycle generation.  The vCPU's VM must use the same
``mm``.  A vCPU can belong to only one execution domain, and ordinary
``KVM_RUN`` is excluded while it is attached.  x86 rejects vCPUs that are in
nested guest mode or SMM, or that expose VMX or SVM to the guest.

``KVM_EXEC_CREATE_EXECUTOR`` returns an executor fd and a nonzero executor
generation.  ``executor_cookie`` is returned in queries but is not a policy
input.  ``KVM_EXECUTOR_F_STRICT_CPU`` requires every run to occur on
``requested_cpu``; migration causes an observable return.  Without that flag,
``KVM_EXEC_CPU_ANY`` allows normal Linux placement.

Capsule ownership is exclusive.  At most one executor may own a capsule, and
one executor owns at most one capsule.  Closing an executor releases its
ownership.  Closing a domain begins teardown, wakes runners and retains the
attached vCPU references until the last domain object is released.

Feature negotiation
===================

``KVM_CHECK_EXTENSION(KVM_CAP_VCPU_EXEC_DOMAIN)`` returns the supported
feature mask on x86-64 and zero elsewhere.  The current dependencies are:

* ``CROSS_VM_CHAIN`` requires ``INTRA_VM_CHAIN``;
* ``SYNC_EXITS`` requires ``DYNAMIC_DISPATCH``;
* ``ASYNC_PIO_WRITE`` requires ``DYNAMIC_DISPATCH`` and ``SYNC_EXITS``;
* ``RETURN_KICK`` and ``EXACT_INTERRUPT`` require ``DYNAMIC_DISPATCH``;
* ``INTERRUPT_PUBLICATION`` requires ``EXACT_INTERRUPT``; and
* ``LIFECYCLE_STATE`` requires ``DYNAMIC_DISPATCH`` and ``SYNC_EXITS``.

Negotiation is exact: the kernel rejects unsupported requested bits and
returns the accepted mask in ``negotiated_features``.  Userspace must not infer
one feature from another beyond the dependencies above.

Run interfaces
==============

``KVM_EXEC_RUN`` runs one exact capsule.  ``request_sequence``, domain and
executor generations, capsule id and capsule lifecycle generation must all be
valid.  KVM reports the return reason, ordinary KVM run result and exit reason,
current CPU, and exact owned capsule on return.

``KVM_EXEC_RUN_TRACE`` is a bounded deterministic conformance interface.  It
repeats a userspace array of exact capsule identities up to
``KVM_EXEC_TRACE_MAX_STEPS`` and reports completed steps and timing counters.
It is not a kernel scheduler and never selects an alternate capsule.
Cross-VM entries require the negotiated cross-VM feature.

``KVM_EXEC_RUN_DISPATCH`` consumes exact commands from the mapped command
ring.  ``SWITCH`` names the expected current capsule and exact target;
``RELEASE`` names the expected current capsule and no target.  Every command
has a strictly increasing nonzero request sequence and receives one terminal
completion.  Important completion states include:

* ``APPLIED``: the exact ownership change was installed;
* ``RETURNED``: release completed and the executor owns no capsule;
* ``CANCELLED_BEFORE_APPLY``: cancellation won before ownership changed;
* ``CURRENT_MISMATCH`` or ``TARGET_*``: an identity, lifecycle or ownership
  precondition failed;
* ``EXIT_PENDING``: the issuing capsule has an incomplete userspace exit.

A submission alone is not proof that ownership changed.  Userspace must
consume the matching completion and reconcile an ambiguous timeout with query
state.  Cancellation after ``APPLIED`` cannot roll ownership back.

Mapped transport
================

An executor with ``DYNAMIC_DISPATCH`` maps exactly
``KVM_EXEC_DISPATCH_MMAP_SIZE`` bytes at offset zero with shared read/write
permissions.  The fixed ABI-v2 layout contains the header, command ring,
completion ring, exit-request ring and exit-completion ring at the offsets in
``linux/kvm.h``.  The header reports entry counts and sizes; userspace must
validate them before publishing any entry.

Each ring is single-producer/single-consumer:

* userspace produces commands and consumes command completions;
* KVM consumes commands and produces command completions;
* KVM produces exit requests and consumes exit completions;
* userspace consumes exit requests and produces exit completions.

A producer fills an entry and release-stores the tail.  A consumer
acquire-loads the tail before reading an entry and release-stores the head
after consuming it.  Indices are monotonically increasing ``u64`` counters;
the slot is selected modulo ``KVM_EXEC_DISPATCH_RING_ENTRIES``.  Nonzero
reserved fields, malformed header geometry, invalid monotonic distances and
entry identity mismatches fail closed.  KVM records detected corruption in
the mapped header and returns ``KVM_EXEC_RETURN_DISPATCH_CORRUPT``.

``KVM_EXEC_KICK`` wakes a dispatcher after command publication.  With
``KVM_EXEC_KICK_F_RETURN_TO_VMM`` it requests a controlled userspace return;
otherwise it is only a dispatcher wake.  A late return request may be
coalesced with an already published mapped exit, but an ownership-changing
command is still required before another capsule can run.

Exit completion
===============

With ``SYNC_EXITS``, every returned PIO/MMIO exit has a nonzero
capsule-local exit sequence and remains bound to its issuing capsule.  A
completion-bearing exit must be applied through that capsule's authoritative
``kvm_run`` mapping exactly once before the capsule reenters.  Switching,
release, detach, drain and incompatible state ioctls reject while such a
completion is pending.

``ASYNC_PIO_WRITE`` moves only bounded PIO writes through the mapped exit
rings.  The request carries immutable capsule, generation, port, width, count,
data and exit-sequence metadata.  Userspace returns a matching
``KVM_EXEC_EXIT_COMPLETE_OK`` completion.  Reads, MMIO and unsupported or
backpressured exits use the synchronous return path.  Ring pressure increments
the observable fallback counter; it does not drop an exit.

Interrupts and blocked capsules
===============================

``KVM_EXEC_INTERRUPT`` queues one vector for the exact currently owned
capsule, lifecycle generation and executor generation.  The request sequence
is nonzero and generation checked.  KVM never chooses a different target.
If injection is blocked, the normal interrupt-window mechanism remains
authoritative.

``KVM_EXEC_INTERRUPT_F_RETAIN_HLT`` permits the forced-preempt path to retain
the exact capsule's subsequent HLT inside the dispatcher.  A later
ownership-changing command may supersede an unapplied pending interrupt;
same-capsule reentry preserves it.  This is an execution mechanism only.  The
kernel does not assign semantic meaning such as a scheduler park acknowledgment
to HLT or any other exit.

An ordinary ``KVM_INTERRUPT`` remains allowed for an attached vCPU and is
serialized by the vCPU mutex.  Other vCPU state-mutating ioctls require the
domain to be paused, the capsule not running and no completion pending.

When ``KVM_EXEC_FEATURE_INTERRUPT_PUBLICATION`` is negotiated,
``KVM_EXEC_QUERY_INTERRUPT_PUBLICATION`` returns accepted and delivered
counts, the last accepted request sequence, acceptance and delivery
``ktime_get_ns()`` timestamps, and the actual delivery action.  A successful
exact-interrupt ioctl updates both counts exactly once.  The query is
observability only; it neither submits nor retries an interrupt.

Lifecycle and queries
=====================

``KVM_EXEC_PAUSE`` stops new execution and wakes runners.
``KVM_EXEC_DRAIN`` waits until active runs and pending exit completions are
gone.  ``KVM_EXEC_RESUME`` admits execution again.  A lifecycle-safe detach is
therefore pause, drain, detach, then resume when the domain remains usable.

``KVM_EXEC_QUERY_CAPSULE`` reports exact lifecycle identity, ownership,
blocked reason, exit sequence, run/exit/halt/wake counters, runtime and last
CPU.  ``KVM_EXEC_QUERY_EXECUTOR`` reports exact executor identity, current
owner, lifecycle state, run/switch/release/reject/cancel/exit/failure counters,
runtime and exact-interrupt counters.
``KVM_EXEC_QUERY_INTERRUPT_PUBLICATION`` separately reconciles exact request
acceptance with the delivery action.  Query state is the reconciliation
authority after userspace loses a completion or observes a timeout.

Compatibility and reserved fields
=================================

Every ioctl structure starts with ``size`` and ``flags``.  The current
experimental ABI requires ``size == sizeof(struct)``; flags are rejected
unless explicitly documented.  All reserved input fields must be zero, and
the kernel zeroes reserved output fields.  Fixed-width UAPI types and
``__aligned_u64`` pointers make the implemented compat ioctl use the same
layout.  Userspace must nevertheless negotiate the capability and feature
mask rather than relying on ioctl numbers alone.

Unsupported architectures, feature combinations, guest configurations,
ownership states and pending completions return errors or explicit completion
statuses.  There is no implicit fallback target and no dependency on a
particular userspace scheduler or host CPU allocator.
