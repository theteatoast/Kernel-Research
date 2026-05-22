# Chasing a Linux Kernel LPE: When a userfaultfd Bug Becomes Security-Relevant

A while back, while digging through Linux kernel memory management internals, I noticed something odd in the `userfaultfd` retry path.

At first, it looked like the kind of primitive that might be exploitable for privilege escalation.

After building a proof of concept, reporting it upstream, and discussing it with kernel maintainers, the final conclusion was more nuanced.

The underlying behavior is real.

The primitive works.

But whether it is actually a security vulnerability depends heavily on the environment and assumptions around it.

This writeup documents the research process, the technical issue, the PoC, and what I learned from the experience.

---

## How This Started

I was looking through the Linux kernel's `userfaultfd` implementation, specifically the `UFFDIO_COPY` path.

One part of the logic immediately stood out.

The rough flow looked like this:

- a destination VMA gets validated
- a folio gets allocated for that mapping
- execution enters a retry path
- locks get dropped
- another thread can modify the memory layout
- execution resumes
- the previously allocated folio is reused

That raised an obvious question:

**What happens if the destination VMA changes while the kernel has dropped its locks?**

More specifically:

**Can a folio allocated for one backing object end up getting inserted into another backing object's page cache?**

If yes, that would be a very strange primitive.

So I started digging.

---

## The Core Issue

The interesting behavior lives in:

`mm/userfaultfd.c`

Specifically:

`mfill_copy_folio_retry()`

The suspected issue looked like this:

1. `UFFDIO_COPY` begins for a shmem-backed mapping
2. kernel resolves the original VMA
3. folio allocation happens for inode A
4. retry logic drops locks
5. another thread replaces the destination mapping with `mmap(MAP_FIXED)`
6. kernel resumes
7. no validation confirms the backing file is still identical
8. folio insertion proceeds

The existing validation logic checked compatibility using `vma_uffd_ops()`.

At first glance, that sounds reasonable.

But that does **not** guarantee object identity.

Two different shmem-backed mappings can share the same userfaultfd ops pointer.

So checking:

```c
vma_uffd_ops(old_vma) == vma_uffd_ops(new_vma)
```

is not equivalent to checking:

```c
old_vma->vm_file == new_vma->vm_file
```

That distinction was the core of the hypothesis.

---

## Building a Proof of Concept

Before thinking about impact, I wanted to prove the primitive itself.

The question was simple:

**Can attacker-controlled data be injected into a different inode's page cache?**

The PoC workflow:

- create memfd A
- create memfd B
- register `userfaultfd`
- trigger `UFFDIO_COPY`
- intentionally block the retry path
- swap the destination VMA using `mmap(MAP_FIXED)`
- resume execution
- inspect memfd B

The result was deterministic.

No unreliable race timing.
No repeated brute force attempts.
No probabilistic behavior.

Single-shot success.

Attacker-controlled contents from one context ended up inside a different backing inode's page cache.

That confirmed the primitive.

---

## Why This Looked Interesting

Once the primitive was confirmed, the obvious next question was:

**Can this cross a meaningful security boundary?**

A few ideas came up.

### Shared tmpfs IPC

A privileged process consuming data from shared tmpfs-backed IPC is immediately interesting.

Examples:

- `/dev/shm`
- temporary IPC files
- badly designed local daemons
- writable shared communication channels

If attacker-controlled data could be injected into something later trusted by a privileged process, that becomes much more interesting.

---

### memfd assumptions

Another angle was integrity expectations around memfd-backed objects.

If a path exists where page cache state can be manipulated unexpectedly, that creates confusion around what application developers think object integrity guarantees actually mean.

---

### Container edge cases

Shared memory assumptions inside containers can be messy.

Weak IPC design, shared tmpfs usage, namespace mistakes, or bad isolation assumptions can make odd kernel primitives much more useful than they first appear.

---

## The Demo Exploit

To test exploitability, I built a demonstration.

Setup:

- privileged daemon reads commands from `/dev/shm`
- attacker injects controlled command content
- daemon executes the payload
- payload creates a setuid root shell

That worked.

But this needs an important disclaimer.

This is **not** evidence of a universal Linux local privilege escalation.

The victim model is intentionally unsafe.

The exploit depends on assumptions outside the kernel primitive itself.

The actual interesting part is the cross-inode injection primitive.

The exploit chain is just one hypothetical abuse scenario.

That distinction matters.

---

## Reporting Upstream

I reported the issue upstream as a potential security vulnerability.

The report described:

- cross-inode page cache injection
- deterministic reproduction
- attacker-controlled content insertion
- no race timing dependency
- possible security implications

One of the first questions raised was:

> Doesn't the original privileged file have to be opened with O_RDWR by the attacker at the first place?

That was a fair challenge.

Because exploitability depends heavily on what access assumptions are already true.

I clarified that the privileged execution demo was just one demonstration path.

The actual concern was the kernel-side object confusion behavior.

The final response from upstream:

> All that said, this is not a vulnerability, it's a bug we are already aware of and we are already discussing the ways to fix it.

That was the final verdict.

---

## So Was It Actually a Vulnerability?

The honest answer:

**It depends.**

In the general case, no.

The maintainers were right.

A weird kernel primitive is not automatically a security vulnerability.

If all you have is:

- cross-inode page cache injection
- into attacker-controlled objects
- or targets already writable by the attacker

then this is a correctness bug.

But if the surrounding environment introduces:

- unsafe privileged consumers
- weak IPC design
- shared trust boundaries
- assumptions about immutable object identity

then the exact same primitive becomes much more security relevant.

So the better framing is:

**A kernel bug that can become security-relevant under the right conditions.**

That is very different from calling it a universal LPE.

---

## Potential Fix

A straightforward hardening idea would be validating that the backing file remains identical after retry.

Something like:

```c
if (state->vma->vm_file != orig_file)
    return -EAGAIN;
```

If locks are dropped and execution resumes later, object identity should be explicitly revalidated.

Not inferred indirectly.

---

## Lessons Learned

This was a useful reminder that kernel research is not just about finding weird behavior.

It's about understanding impact.

A technically interesting primitive does not automatically become a security issue.

The real questions are:

- does this cross a real trust boundary?
- can attacker reach meaningful targets?
- are the assumptions realistic?
- does exploitation require an already broken environment?

That gap between "interesting bug" and "real vulnerability" matters a lot.

---

## Why I'm Publishing This Anyway

Even though upstream did not classify this as a security vulnerability, I still think the research is worth documenting.

Because this is what real research often looks like.

You find weird behavior.

You build a hypothesis.

You write a PoC.

You test assumptions.

You discuss with maintainers.

Sometimes the result is a security issue.

Sometimes it is not.

Both outcomes are valuable.

The research process still matters.

---

## PoC

The proof of concept is included in this repository.

Build:

```bash
gcc -O2 -pthread -o cross_inode_poc cross_inode_poc.c
```

Run primitive demo:

```bash
./cross_inode_poc
```

Victim simulation:

```bash
sudo ./cross_inode_poc --victim
```

Exploit demonstration:

```bash
./cross_inode_poc --root
```

---

## Disclaimer

This research is shared for educational and defensive analysis purposes.

The exploit demonstration intentionally uses an unsafe victim model and should not be interpreted as a general Linux local privilege escalation vulnerability.