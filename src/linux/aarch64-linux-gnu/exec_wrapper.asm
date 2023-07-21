// Runs another the executable from argv[1:], copying envp. Designed to use as little physical memory
// possible. On error, returns an exit code equal to errno.

.arch armv8-a

.global _start
_start:
	mov w8, 221  // execve
	add x1, sp, 16  // argv <- argv + 1
	ldr x0, [x1]  // pathname <- argv[1]
	ldr x2, [sp]  // envp <- argv + argc + 1
	add x2, x1, x2, lsl 3
	svc #0

	neg x0, x0  // status
	mov w8, 93  // exit
	svc #0

	// if, for some reason, exit(2) fails, don't keep going
	hlt #0
	udf #0
	b .
