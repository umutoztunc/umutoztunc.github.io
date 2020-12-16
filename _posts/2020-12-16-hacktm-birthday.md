---
layout: post
title: "HackTM CTF Finals 2020 / Birthday"
permalink: /hacktm-finals-2020-birthday
---

As soon as reading the challenge name, I started to think whether I can perform a [Birthday Attack](https://en.wikipedia.org/wiki/Birthday_attack).

Let's take a look at the source first:
```python
#!/usr/bin/env python3

import os, sys
import binascii
from speck import SpeckCipher

rand_int = lambda x: int.from_bytes(os.urandom(x), 'little')
cipher = SpeckCipher(rand_int(8), key_size=64, block_size=32, mode='CBC', init=rand_int(4))

FLAG = 'REAL_FLAG_GOES_HERE'
content = FLAG.ljust(4*50, '!')

while True:
  for i in range(0, len(content), 4):
    v = cipher.encrypt(int.from_bytes(content[i:i+4].encode(), 'big'))
    sys.stdout.write('{:x}'.format(v).rjust(8, '0'))
```

As you can see above, the flag gets encrypted with 32-bit block cipher. The key and the iv are both randomized. Note that we can get lots of encrypted blocks from the remote server since the encryption happens in an infinite loop.

According to the birthday attack, we expect to have at least one collision in approximately 2<sup>16</sup> blocks.


Let C<sub>i</sub> be the *i*th ciphertext block and M<sub>i</sub> be the *i*th plaintext block. CBC mode implies the equation:

<div align="center">
C<sub>i</sub> = E(key, M<sub>i</sub> XOR C<sub>i-1</sub>)
</div>

Let's assume C<sub>i</sub> and C<sub>j</sub> collides where i != j.

<div align="center">
C<sub>i</sub> = C<sub>j</sub>
<br>
E(key, M<sub>i</sub> XOR C<sub>i-1</sub>) = E(key, M<sub>j</sub> XOR C<sub>j-1</sub>)
<br>
M<sub>i</sub> XOR C<sub>i-1</sub> = M<sub>j</sub> XOR C<sub>j-1</sub>
<br>
M<sub>i</sub> XOR M<sub>j</sub> = C<sub>i-1</sub> XOR C<sub>j-1</sub>
</div>

If we know either M<sub>i</sub> or M<sub>j</sub>, we can calculate the other one using the above equation. Since the flag is padded with exclamation marks, we can assume that we know the last block of the plaintext.

In order to perform the attack, we can collect a million encrypted blocks and store the collision indexes. Then, we will try to find plaintext blocks and repeat this process until there are no unknown blocks left.

Here is the full attack script:
```python
#!/usr/bin/env python3
from pwn import *
from binascii import a2b_hex

r = remote('34.107.97.76', 60003)
c_to_index = {}
ciphers = []
for i in range(1000000):
    c = int.from_bytes(a2b_hex(r.recvn(8)), 'big')
    if c not in c_to_index:
        c_to_index[c] = list()
    c_to_index[c].append(i)
    ciphers.append(c)

messages = [None] * 50
messages[49] = int.from_bytes(b'!!!!', 'big')
while None in messages:
    for mi in range(50):
        if messages[mi] is None:
            continue
        for ci in range(mi, len(ciphers), 50):
            if ci == 0:
                continue
            for cj in c_to_index[ciphers[ci]]:
                if cj == 0 or ci == cj:
                    continue
                mj = cj % 50
                if mi == mj or messages[mj] is not None:
                    continue
                c1 = ciphers[ci - 1]
                c2 = ciphers[cj - 1]
                messages[mj] = messages[mi] ^ c1 ^ c2

flag = b''
for m in messages:
    flag += m.to_bytes(4, 'big')
print(flag)
```
