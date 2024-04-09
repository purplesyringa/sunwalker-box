Restricting sandboxed processes
===============================

You may have noticed that we didn't explicitly inform the box about our desired restrictions. This means that the box uses (somewhat) insane defaults: it does not, in fact, protect against DoS, as the user process has nearly unlimited access to the resources.

You may choose to not enforce some of the limits, however, you should mind the consequences.

If you don't [enforce time limits](ensuring-termination.html), sunwalker-box may wait for the program termination forever if the program encounters [deadlock](https://en.wikipedia.org/wiki/Deadlock) or infinite loop.

If you don't [enforce commited RAM limit](resources.html), the sandboxed process may commit all the available memory and your system will reach [OOM](https://en.wikipedia.org/wiki/Out_of_memory).

If you don't [enforce processes limit](resources.html), the sandboxed process may execute a [fork bomb](https://en.wikipedia.org/wiki/Fork_bomb) and the host system may become unusable and unresponsible.

If you don't [enforce filesystem quotas](filesystem-quotas.html), reasonable defaults will be used. You may wish to tweak them. Bear in mind that the sandboxed filesystem exitsts only in RAM and launching too many sandboxes in this case may lead to the same consequences as the unenforced commited RAM limit.
