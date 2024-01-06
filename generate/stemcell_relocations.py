import struct
import sys

with open(sys.argv[1], "rb") as f:
    elf = f.read()


indices = []

for i in range(0, len(elf) - 7):
    word, = struct.unpack("Q", elf[i:i + 8])
    if 0 <= word - 0xdeadbeef000 <= 0x1000000:
        indices.append(i)

print(indices)
