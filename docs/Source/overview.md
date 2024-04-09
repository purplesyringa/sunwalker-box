Hello, this is sunwalker-box! 👋
================================

sunwalker-box is a next generation sandbox for running untrusted programs completely isolated, primarily for competitive programming competitions.

Most general-purpose sandboxes prioritize protection from permanent damage and don't care if the sandboxed process causes denial of service, e.g. by allocating lots of memory, using all cores of the CPU, or running a fork bomb.

They are also usually optimized for long-running tasks, when the time the sandbox takes to start does not really matter. For instance, Docker and Podman take about half a second to run hello-world.

In contrast, competitive-programming-themed sandboxes typically protect against DoS attacks and common vulnerabilities, but little else: there are often ways to circumvent some of protections using slightly non-trivial OS features. They are also seldom extensible.

Finally, sandboxes seldom prioritize efficiency. We can do much better than recreating a sandbox and restarting the same program from the filesystem a hundred times. And while tricks such as preforking might not increase the performance by a lot, optimizations do accumulate.

sunwalker-box is a relatively small (less than a megabyte in size) and portable ([build](building.html) once and use almost everywhere) executable.
