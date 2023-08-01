# TODO: handle multiarch gracefully instead of killing the process
A = arch
A == ARCH_X86_64 ? next : kill

A = sys_number

A == msgget ? trace : next
A == semget ? trace : next
A == shmget ? trace : next
A == memfd_create ? trace : next

# Forbid x86-32 ABI in x86-64 mode
A &= 0x40000000
A == 0 ? next : kill

allow:
return ALLOW

trace:
return TRACE

kill:
return KILL
