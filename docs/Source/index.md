sunwalker-box, a next generation isolation box
==============================================

This is a sandbox for running untrusted programs completely isolated, primarily for competitive programming competitions. This sandbox is used by sunwalker, but may just as well be used for your projects.

Licensed under Apache 2.0.


Why sunwalker-box?
------------------

> TL;DR: sunwalker-box is more secure than some sandboxes and faster than others, provided that the invoked tasks are homogenous, that is, the same program is invoked in the same environment with slightly different configuration, e.g. input.

Most general-purpose sandboxes prioritize protection from permanent damage and don't care if the sandboxed process causes denial of service, e.g. by allocating lots of memory, using all cores of the CPU, or running a fork bomb.

They are also usually optimized for long-running tasks, when the time the sandbox takes to start does not really matter. For instance, Docker and Podman take about half a second to run hello-world.

In contrast, competitive-programming-themed sandboxes typically protect against DoS attacks and common vulnerabilities, but little else: there are often ways to circumvent some of protections using slightly non-trivial OS features. They are also seldom extensible.

Finally, sandboxes seldom prioritize efficiency. We can do much better than recreating a sandbox and restarting the same program from the filesystem a hundred times. And while tricks such as preforking might not increase the performance by a lot, optimizations do accumulate.

