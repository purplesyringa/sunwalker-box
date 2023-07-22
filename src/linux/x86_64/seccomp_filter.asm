# TODO: handle multiarch gracefully instead of killing the process
A = arch
A == ARCH_X86_64 ? next : kill

A = sys_number

A == msgget ? trace : next
A == semget ? trace : next
A == shmget ? trace : next
A == memfd_create ? trace : next

allow:
return ALLOW

trace:
return TRACE

kill:
return KILL
