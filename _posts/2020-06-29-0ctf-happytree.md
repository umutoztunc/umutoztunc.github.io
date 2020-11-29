---
layout: post
title: "0CTF 2020 / Happy Tree"
permalink: /0ctf-2020-happytree
---

At first, I noticed that there were no calls to `puts` or `scanf` in the analysis of IDA. Thus, I decided to put a breakpoint on `write` to see how it gets called. However, software breakpoints caused the binary to terminate early for some reason. Therefore, I set a hardware breakpoint on `write` and checked its return address.

I noticed that most functions were not identified by IDA, so I have manually created them and found this interesting subroutine:
```c
_DWORD *set_table()
{
  _DWORD *ptable; // eax

  ptable = table;
  table[2] = &puts;
  table[7] = 0;
  table[6] = 0;
  table[3] = 0;
  table[1] = &_isoc99_scanf;
  table[0] = &memset;
  table[9] = &input;
  table[5] = "%36s";
  table[8] = "Wow!";
  table[4] = "Ah?";
  return ptable;
}
```
So, the binary calls `scanf` to read our input. Since the challenge name is `happy tree`, it might be possible that this is a tree structure. For example, index `i` might be the parent of both `2*(i+1)-1` and `2*(i+1)` etc. 

Anyway, at this point I tried to write a simple angr script, because why not? We know by running the program that it says `Ow!` when the input is wrong, and according to the strings above, it might be printing `Wow!` for the correct input. Using these two information I wrote the following angr script:

```python
#!/usr/bin/env python
import angr

p = angr.Project('./happy_tree', auto_load_libs=False)
st = p.factory.entry_state()
simgr = p.factory.simgr(st)
simgr.explore(
        find=lambda s: b"Wow!" in s.posix.dumps(1),
        avoid=lambda s: b"Ow!" in s.posix.dumps(1),
        step_func=lambda lsm: lsm.drop(stash='avoid'))

if len(simgr.found) > 0:
    print('Found!')
    print(simgr.found[0].posix.dumps(0))
else:
    print('Failed.')

```

The script took forever to complete, so I gave up on angr and got back to IDA. Then, I found this function:

```c
int __cdecl vm_step(int a1)
{
  unsigned int v1; // edi
  unsigned int v2; // eax
  int result; // eax

  v1 = (*(int (__cdecl **)(_DWORD, _DWORD))(**(_DWORD **)(a1 + 16) + 8))(**(_DWORD **)(a1 + 16), 0);
  v2 = (*(int (__cdecl **)(_DWORD, _DWORD))(*(_DWORD *)(*(_DWORD *)(a1 + 16) + 4) + 8))(
         *(_DWORD *)(*(_DWORD *)(a1 + 16) + 4),
         0);
  switch ( *(_DWORD *)a1 )
  {
    case 0:
      result = v1 == v2;
      break;
    case 1:
      result = v1 << v2;
      break;
    case 2:
      result = v1 >> v2;
      break;
    case 3:
      result = v1 ^ v2;
      break;
    case 4:
      result = v1 + v2;
      break;
    case 5:
      result = v1 - v2;
      break;
    case 6:
      result = v1 * v2;
      break;
    case 7:
      result = v1 != 0 && v2 != 0;
      break;
    case 8:
      result = v1 < v2;
      break;
    case 9:
      *(_DWORD *)v1 = v2;
      result = 0;
      break;
    default:
      exit(0);
      return result;
  }
  return result;
}
```

This is a simple vm that supports 10 operations. Since I was unable to find vm context, I decided to write a gdb script to log all vm operations:

```python
#!/usr/bin/env python
import gdb
from struct import pack

gdb.execute('start')
#gdb.execute('brva 0x1b6a6')
gdb.execute('hbreak *0x565706a6')

f = open('log.txt', 'w')

while True:
    gdb.execute('continue')

    opcode = int(gdb.parse_and_eval('*(int*)$esi'))
    op1 = int(gdb.parse_and_eval('$edi')) % 2 ** 32
    op2 = int(gdb.parse_and_eval('$eax')) % 2 ** 32

    if opcode == 0:
        f.write('check 0x{:>08x} == 0x{:>08x}'.format(op1, op2))
    elif opcode == 1:
        f.write('0x{:>08x} << 0x{:>08x}\t\tresult = 0x{:>08x}'.format(op1, op2, (op1 << op2) % 2 ** 32))
    elif opcode == 2:
        f.write('0x{:>08x} >> 0x{:>08x}\t\tresult = 0x{:>08x}'.format(op1, op2, (op1 >> op2) % 2 ** 32))
    elif opcode == 3:
        f.write('0x{:>08x} ^ 0x{:>08x}\t\tresult = 0x{:>08x}'.format(op1, op2, (op1 ^ op2) % 2 ** 32))
    elif opcode == 4:
        f.write('0x{:>08x} + 0x{:>08x}\t\tresult = 0x{:>08x}'.format(op1, op2, (op1 + op2) % 2 ** 32))
    elif opcode == 5:
        f.write('0x{:>08x} - 0x{:>08x}\t\tresult = 0x{:>08x}'.format(op1, op2, (op1 - op2) % 2 ** 32))
    elif opcode == 6:
        f.write('0x{:>08x} * 0x{:>08x}\t\tresult = 0x{:>08x}'.format(op1, op2, (op1 * op2) % 2 ** 32))
    elif opcode == 7:
        f.write('check 0x{:>08x} != 0 and 0x{:>08x} != 0'.format(op1, op2))
    elif opcode == 8:
        f.write('check 0x{:>08x} < 0x{:>08x}'.format(op1, op2))
    elif opcode == 9:
        f.write("memory[0x{:>08x}] = 0x{:>08x} ('{}')".format(op1, op2, pack('<I', op2)))
    else:
        f.write('exit')
        break

f.close()
gdb.execute('quit')
```

I let it run for ~7 hours, but the script was still running when I was back. So, I stopped it, but kept the partial log. 

At this point, [@Anciety](https://twitter.com/Anciety2) suggested me to take a look at QDBI which lead me to [this](https://blog.quarkslab.com/slaying-dragons-with-qbdi.html) write-up. My goal was to successfully log all the vm operations. However, after spending hours on Frida + QDBI configuration, I was still receiving libQDBI.so errors. I decided to give up on this and started thinking about instruction counting attack similar to that write-up.

The first tool that came to my mind was `perf`, but it did not work for some reason. The other tool was Intel's `pin`, and luckily I've found this awesome tool called [PinCTF](https://github.com/ChrisTheCoolHut/PinCTF).

After, running it I got the following:

```
Num  : Instr Count    AAAAAAAAAAAAAAAAAAAAAAAAA
2    : 1112893268
1    : 1112893238
4    : 1112893319
3    : 1112893290
5    : 1112893350
6    : 1112893380
8    : 1112893431
7    : 1112893402
10   : 1112893492
9    : 1112893462
11   : 1112893514
12   : 1112893543
13   : 1112893574
14   : 1112893604
15   : 1112893626
16   : 1112893655
18   : 1112893716
17   : 1112893686
19   : 1112893738
20   : 1112893767
22   : 1112893828
21   : 1112893798
24   : 1112893879
23   : 1112893850
26   : 1112893940
25   : 1112893910
27   : 1112893962
28   : 1112893991
30   : 1112894052
29   : 1112894022
31   : 1112894074
32   : 1112894103
33   : 1112894134
34   : 1112894164
35   : 1112894186
36   : 1112894174
[+] Found Num 35 : Count 1112894186
```

We might say that it kind of verified the input length, but the actual attack failed in both directions. At this point, I decided to modify my gdb script to log only `equals` operations as follows:

```python
#!/usr/bin/env python
import gdb
from struct import pack

xor_addr = 0x56570710
equals_addr = 0x565706e0
both_non_zero_addr = 0x56570738

gdb.execute('start')
#gdb.execute('hbreak *' + hex(xor_addr))
gdb.execute('hbreak *' + hex(equals_addr))
#gdb.execute('hbreak *' + hex(both_non_zero_addr))

f = open('log.txt', 'w')

while True:
    try:
        gdb.execute('continue')

        pc = int(gdb.parse_and_eval('$eip')) % 2 ** 32
        op1 = int(gdb.parse_and_eval('$edi')) % 2 ** 32
        op2 = int(gdb.parse_and_eval('$eax')) % 2 ** 32
    except:
        break

    if pc == equals_addr:
        f.write('check 0x{:>08x} == 0x{:>08x}\n'.format(op1, op2))
    elif pc == xor_addr:
        f.write('0x{:>08x} ^ 0x{:>08x}\t\tresult = 0x{:>08x}\n'.format(op1, op2, (op1 ^ op2) % 2 ** 32))
    elif pc == both_non_zero_addr:
        f.write('check 0x{:>08x} != 0 and 0x{:>08x} != 0\n'.format(op1, op2))
    else:
        break

f.close()
gdb.execute('quit')
```

Here is the result I got for the input `'A' * 36`:

```
check 0x121eda9a == 0xa25dc66a
check 0x6d4416c0 == 0x00aa0036
check 0x121eda9a == 0xc64e001a
check 0x6d4416c0 == 0x369d0854
check 0x121eda9a == 0xf15bcf8f
check 0x6d4416c0 == 0x6bbe1965
check 0x121eda9a == 0x1966cd91
check 0x6d4416c0 == 0xd4c5fbfd
check 0x121eda9a == 0xb04a9b1b
```

It is obvious that left-side of the comparison comes from our input and right-side belongs to the flag. We have 9 32-bit blocks to deal with. Notice that odd and even indexes result in different values. At this point, I decided to check my partial log which was left by my first script. Here is the beginning of it:

```
memory[0x56582c10] = 0x41414141 ('b'AAAA'')
memory[0x56582c00] = 0x00000000 ('b'\x00\x00\x00\x00'')
check 0x00000000 < 0x000186a0
0x41414141 << 0x0000000d		result = 0x28282000
0x41414141 ^ 0x28282000		result = 0x69696141
0x41414141 << 0x0000000d		result = 0x28282000
0x41414141 ^ 0x28282000		result = 0x69696141
0x69696141 >> 0x00000011		result = 0x000034b4
0x69696141 ^ 0x000034b4		result = 0x696955f5
0x41414141 << 0x0000000d		result = 0x28282000
0x41414141 ^ 0x28282000		result = 0x69696141
0x41414141 << 0x0000000d		result = 0x28282000
0x41414141 ^ 0x28282000		result = 0x69696141
0x69696141 >> 0x00000011		result = 0x000034b4
0x69696141 ^ 0x000034b4		result = 0x696955f5
0x696955f5 << 0x00000005		result = 0x2d2abea0
0x696955f5 ^ 0x2d2abea0		result = 0x4443eb55
memory[0x56582c10] = 0x4443eb55 ('b'U\xebCD'')
0x00000000 + 0x00000001		result = 0x00000001
memory[0x56582c00] = 0x00000001 ('b'\x01\x00\x00\x00'')
check 0x00000001 < 0x000186a0
0x4443eb55 << 0x0000000d		result = 0x7d6aa000
0x4443eb55 ^ 0x7d6aa000		result = 0x39294b55
0x4443eb55 << 0x0000000d		result = 0x7d6aa000
0x4443eb55 ^ 0x7d6aa000		result = 0x39294b55
0x39294b55 >> 0x00000011		result = 0x00001c94
0x39294b55 ^ 0x00001c94		result = 0x392957c1
0x4443eb55 << 0x0000000d		result = 0x7d6aa000
0x4443eb55 ^ 0x7d6aa000		result = 0x39294b55
0x4443eb55 << 0x0000000d		result = 0x7d6aa000
0x4443eb55 ^ 0x7d6aa000		result = 0x39294b55
0x39294b55 >> 0x00000011		result = 0x00001c94
0x39294b55 ^ 0x00001c94		result = 0x392957c1
0x392957c1 << 0x00000005		result = 0x252af820
0x392957c1 ^ 0x252af820		result = 0x1c03afe1
memory[0x56582c10] = 0x1c03afe1 ('b'\xe1\xaf\x03\x1c'')
0x00000001 + 0x00000001		result = 0x00000002
memory[0x56582c00] = 0x00000002 ('b'\x02\x00\x00\x00'')
check 0x00000002 < 0x000186a0
0x1c03afe1 << 0x0000000d		result = 0x75fc2000
```

It starts with an 32-bit block from our input and does something 0x186a0 times in a loop. If we rewrite the loop-body in python, we get:

```python
mask = 0xFFFFFFFF
x = 0x41414141
for i in range(0x186a0):
    a = (x << 0xd) & mask
    a = (a ^ x) & mask
    b = (a >> 0x11) & mask
    b = (b ^ a) & mask
    c = (b << 5) & mask
    x = (b ^ c) & mask
```
This can be simplified as:
```python
mask = 0xFFFFFFFF
x = 0x41414141
for i in range(0x186a0):
    x = (x ^ (x << 0xd)) & mask
    x = (x ^ (x >> 0x11)) & mask
    x = (x ^ (x << 5)) & mask
```

After running this code, I got the value `0x121eda9a` which is the same value as the left-value of the first check, great!

Now, we need a decryption routine which is simple. If we left shift a number by n bits and xor it with itself, the lowest n bits will stay the same. So, we already know the original lowest n bits. Since, we shifted the value before xor operation, the next n bits were actually xored with the previous n bits that we recovered. As a result, we can calculate the next n bits simply by xoring them with the previous recovered n bits. Now, we know the lowest 2n bits of the original value. We can repeat this process until we recover the original value completely.

The same approach applies to right-shift, we just need to start recovering from the highest n bits in that case.

Here we can create two functions to decrypt both cases:

```python
def undo_left_xor(x, n):
    bitmask = (1 << n) - 1
    for i in range(32 / n + 1):
        found_bits = x & bitmask
        x ^= found_bits << n
        bitmask <<= n
    return x & 0xFFFFFFFF


def undo_right_xor(x, n):
    bitmask = ((1 << n) - 1) << (32 - n)
    for i in range(32 / n + 1):
        found_bits = x & bitmask
        x ^= found_bits >> n
        bitmask >>= n
    return x & 0xFFFFFFFF
```

However, we are not done yet. This will only work for even-indexed blocks. We still need to understand how our input results in a different value for odd-indexed ones.

Two different possibilities popped in my head:
- The input might be xored with a secret value **after** the encryption loop.
- Or, it might get xored with a secret value **before** the encryption loop.

If it is the first case, then the secret value must be `0x121eda9a ^ 0x6d4416c0` which is `0x7f5acc5a`. For the second case then the secret value must be `decrypt(0x6d4416c0) ^ 0x41414141` which is `0xAAAAAAAA`.

It turned out that both approaches successfully work. I have chosen to use the first one in my script. Here is my final script:

```python
#!/usr/bin/env python
from struct import pack

encrypted = [
    0xa25dc66a, 0x00aa0036, 0xc64e001a,
    0x369d0854, 0xf15bcf8f, 0x6bbe1965,
    0x1966cd91, 0xd4c5fbfd, 0xb04a9b1b,
]

mask = 0xFFFFFFFF

def undo_left_xor(x, n):
    bitmask = (1 << n) - 1
    for i in range(32 / n + 1):
        found_bits = x & bitmask
        x ^= found_bits << n
        bitmask <<= n
    return x & 0xFFFFFFFF


def undo_right_xor(x, n):
    bitmask = ((1 << n) - 1) << (32 - n)
    for i in range(32 / n + 1):
        found_bits = x & bitmask
        x ^= found_bits >> n
        bitmask >>= n
    return x & 0xFFFFFFFF

flag = ''
for i, crc in enumerate(encrypted):
    x = crc
    if i % 2:
        x ^= 0x7f5acc5a
    for _ in range(0x186a0):
        x = undo_left_xor(x, 5)
        x = undo_right_xor(x, 0x11)
        x = undo_left_xor(x, 0xd)
    flag += pack('<I', x)

print(flag)
```
