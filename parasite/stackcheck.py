import sys


transitions = []
line_at_address = {}
symbol_to_address = {}

for line in sys.stdin:
    line = line.strip()

    if line.endswith(">:"):
        address, symbol = line[:-2].split(" <")
        symbol_to_address[symbol] = int(address, 16)
        continue

    try:
        address = int(line[:line.index(":")], 16)
        insn = line.split("\t")[2]
    except (IndexError, ValueError):
        continue

    line_at_address[address] = line

    if transitions and transitions[-1][1] is None:
        prev_address, _, stack_manip = transitions[-1]
        transitions[-1] = (prev_address, address, stack_manip)

    insn_name = insn.split()[0]
    stack_manip = 0

    if insn_name in ("jmp", "ja", "jae", "jb", "jbe", "jc", "jcxz", "jecxz", "jrcxz", "je", "jg", "jge", "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js", "jz"):
        target = int(insn.split()[1], 16)
        transitions.append((address, target, 0))
    elif insn_name == "add":
        if insn.endswith(",%rsp"):
            stack_manip = int(insn.split("$")[1].split(",")[0], 16)
    elif insn_name == "sub":
        if insn.endswith(",%rsp"):
            stack_manip = -int(insn.split("$")[1].split(",")[0], 16)
    elif insn_name == "and":
        # Could be stack alignment
        assert not insn.endswith(",%rsp")
    elif insn_name in ("lea", "mov", "movq"):
        # Could be complicated arithmetic
        assert not insn.endswith(",%rsp")
    elif insn_name == "call":
        target = int(insn.split()[1], 16)
        transitions.append((address, target, -8))
    elif insn_name == "pop":
        stack_manip = 8
    elif insn_name == "push":
        stack_manip = -8

    if insn_name not in ("ud2", "jmp", "ret"):
        transitions.append((address, None, stack_manip))

if transitions[-1][1] is None:
    transitions.pop()


lowest = {}
lowest_next = {}

iteration = 0
while True:
    updated_address = None
    for address, target, stack_manip in transitions:
        new_value = lowest.get(target, 0) + stack_manip
        if new_value < lowest.get(address, 0):
            lowest[address] = new_value
            lowest_next[address] = target, stack_manip
            updated_address = address
    if updated_address is None:
        break
    iteration += 1

    if iteration == len(transitions) + 1:
        print("Cycle in allocations:")
        address = updated_address
        while True:
            print(line_at_address[address])
            address, _ = lowest_next[address]
            if address == updated_address:
                break
        print(line_at_address[address])
        sys.exit(1)


for symbol in sys.argv[1:]:
    address = symbol_to_address[symbol]
    stack_usage = -lowest[address]
    print(symbol, stack_usage)

    print("Nesting leading to this usage:")
    while True:
        if address in lowest_next:
            target, stack_manip = lowest_next[address]
            if stack_manip > 0:
                print(f"[+{stack_manip}]".ljust(10) + line_at_address[address])
            elif stack_manip < 0:
                print(f"[{stack_manip}]".ljust(10) + line_at_address[address])
            else:
                print(" " * 10 + line_at_address[address])
            address = target
        else:
            print(" " * 10 + line_at_address[address])
            break
    print()


# print(lowest)
