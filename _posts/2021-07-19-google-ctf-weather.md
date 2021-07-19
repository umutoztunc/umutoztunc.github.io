---
layout: post
title: "Google CTF 2021 / Weather"
permalink: /google-ctf-2021-weather
---

## 0x00 Overview

This was an interesting and fun challenge. Even though I solved it an hour
after the CTF ended, I decided to publish a write-up for it.

The binary calls `printf("Flag: %F\n");` before it exits which prints
`Flag: none` which suggests that `%F` is a registered conversion specifier.

We can see that the following function is called in `init`:

```c
int extend_printf()
{
  register_printf_function('W', print_wind, arginfo);
  register_printf_function('P', print_precipitation, arginfo);
  register_printf_function('T', print_temperature, arginfo);
  register_printf_function('F', print_flag, arginfo);
  register_printf_function('C', call_handler, dummy_arginfo);
  register_printf_function('M', mov_handler, dummy_arginfo);
  register_printf_function('S', add_handler, dummy_arginfo);
  register_printf_function('O', subt_handler, dummy_arginfo);
  register_printf_function('X', mul_handler, dummy_arginfo);
  register_printf_function('V', div_handler, dummy_arginfo);
  register_printf_function('N', mod_handler, dummy_arginfo);
  register_printf_function('L', shl_handler, dummy_arginfo);
  register_printf_function('R', shr_handler, dummy_arginfo);
  register_printf_function('E', xor_handler, dummy_arginfo);
  register_printf_function('I', and_handler, dummy_arginfo);
  return register_printf_function('U', or_handler, dummy_arginfo);
}
```

This looks like a printf vm. `F` triggers 
`fprintf(stream, "%52C%s", **args, a4);` which makes a call with `C` and prints
the result with `s`.

## 0x01 Disassembler

```nasm
.data:0000000000005080 ; char memory[]
.data:0000000000005080 memory          db '%52C%s',0           ; DATA XREF: mov_handler+3F↑o
.data:0000000000005080                                         ; mov_handler+77↑o ...
.data:0000000000005087 a31hm30le13lm14 db '%3.1hM%3.0lE%+1.3lM%1.4llS%3.1lM%3.2lO%-7.3C',0
.data:00000000000050B4 a04096hhm0255ll db '%0.4096hhM%0.255llI%1.0lM%1.8llL%0.1lU%1.0lM%1.16llL%0.1lU%1.200l'
.data:00000000000050B4                 db 'lM%2.1788llM%7C%-6144.1701736302llM%0.200hhM%0.255llI%0.37llO%020'
.data:00000000000050B4                 db '0.0C',0
```

The above memory section is the vm bytecode. Now, the goal is to write a
disassembler for it. Let's take a look at `mov_handler` to understand how vm
operations work:

```c
int __fastcall mov_handler(FILE *stream, const struct printf_info *info, const void *const *args)
{
  int v4; // [rsp+24h] [rbp-14h]
  int v5; // [rsp+28h] [rbp-10h]
  int src; // [rsp+2Ch] [rbp-Ch]
  char *dst; // [rsp+30h] [rbp-8h]

  v5 = info->width;
  v4 = info->prec;
  if ( (*(info + 12) & 0x20) != 0 )
  {
    dst = &memory[v5];
  }
  else if ( (*(info + 12) & 0x40) != 0 )
  {
    dst = &memory[regs[v5]];
  }
  else
  {
    dst = &regs[v5];
  }
  src = 0;
  if ( (*(info + 13) & 2) != 0 )
  {
    src = *&memory[v4];
  }
  else if ( (*(info + 12) & 2) != 0 )
  {
    src = *&memory[regs[v4]];
  }
  else if ( (*(info + 12) & 1) != 0 )
  {
    src = info->prec;
  }
  else if ( (*(info + 12) & 4) != 0 )
  {
    src = regs[v4];
  }
  *dst = src;
  return 0;
}
```

The structure of all handlers except `call_handler` is the same. It is
`op dst, src` where `dst` can be a register, memory address, or memory address
pointed by a register. The same goes for `src` as well, but in addition, it can
also be an immediate value.

Now, let's take a look at `call_handler`:

```c
nt __fastcall call_handler(FILE *stream, const struct printf_info *info, const void *const *args)
{
  int v4; // [rsp+24h] [rbp-Ch]
  _BOOL4 v5; // [rsp+2Ch] [rbp-4h]

  v4 = info->prec;
  if ( (*(info + 12) & 0x20) != 0 )
  {
    v5 = regs[v4] < 0;
  }
  else if ( (*(info + 12) & 0x40) != 0 )
  {
    v5 = regs[v4] > 0;
  }
  else if ( info->pad == 48 )
  {
    v5 = regs[v4] == 0;
  }
  else
  {
    v5 = 1;
  }
  if ( v5 )
    fprintf(stream, &memory[info->width]);
  return 0;
}
```

At first, it looks like `js`, `jns`, `jz`, and `jmp` operations. However, since
this triggers another printf call, handles it and continues with the rest, it is
more like a conditional call.

Now that we have enough information, we can write a disassembler. However, it is
not an easy task to parse a format string. To avoid that, we can register
handlers to disassemble instructions, then simply iterate through the memory,
find and trigger conversion specifiers with printf, and print the disassembled
instructions along with their addresses.

```c
void disassemble() {
  char temp[256];
  char *code_end = code + sizeof(code);
  char *addr = (char *) memchr(code, '%', sizeof(code));

  while (addr) {
    char *end = strchr(addr + 1, '%');
    // Clear temp before using it.
    memset(temp, 0, sizeof(temp));
    if (end)
      strncpy(temp, addr, end - addr);
    else
      strcpy(temp, addr);

    // Trigger the handler
    if (!strstr(temp, "%s")) {
      printf("0x%04x: ", addr - code);
      printf(temp);
    }
    
    // This is the final format-specifier before the null byte. Since null byte
    // will stop the execution flow, put a ret instruction here.
    if (!end)
      printf("0x%04x: ret\n\n", addr + strlen(addr) - code);
    addr = (char *) memchr(addr + 1, '%', code_end - addr - 1); 
  }
}
```

Here is the disassembly of the bytecode:

```nasm
0x0000: call 0x0034
0x0006: ret

0x0007: mov r3, [r1]
0x000d: xor r3, r0
0x0013: mov [r1], r3
0x001a: add r1, 0x4
0x0021: mov r3, r1
0x0027: sub r3, r2
0x002d: call 0x0007, r3 < 0
0x0033: ret

0x0034: mov r0, [0x1000]
0x003e: and r0, 0xff ; city[0]
0x0047: mov r1, r0
0x004d: shl r1, 0x8
0x0054: or r0, r1
0x005a: mov r1, r0
0x0060: shl r1, 0x10
0x0068: or r0, r1 ; xor key
0x006e: mov r1, 0xc8 ; start
0x0077: mov r2, 0x6fc ; end
0x0081: call 0x0007
0x0084: mov [0x1800], 0x656e6f6e ; 'none'
0x0098: mov r0, [0xc8]
0x00a1: and r0, 0xff
0x00aa: sub r0, 0x25
0x00b2: call 0x00c8, r0 == 0
0x00ba: ret
```

This is a simple xor decryption, it xors the memory region `0xc8-0x6fc` with
the first char of `city`. We can find the key by xoring the original byte at
`0xc8` with '%' and decrypt the memory.

Here is my full C++ code to decrypt and disassemble the whole memory:

```cpp
#include <printf.h>
#include <stdio.h>
#include <string.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using namespace std;

char code[2000];

string parse_src(const struct printf_info *info) {
  stringstream src;
  int src_id = info->prec;

  if ((*((char *)info + 13) & 2) != 0)
    src << "[0x" << hex << src_id << "]";
  else if ((*((char *)info + 12) & 2) != 0)
    src << "[r" << src_id << "]";
  else if ((*((char *)info + 12) & 1) != 0)
    src << "0x" << hex << src_id;
  else if ((*((char *)info + 12) & 4) != 0)
    src << "r" << src_id;
  else
    src << "0";

  return src.str();
}

string parse_dst(const struct printf_info *info) {
  stringstream dst;
  int dst_id = info->width;

  if ((*((char *)info + 12) & 0x20) != 0)
    dst << "[0x" << hex << dst_id << "]";
  else if ((*((char *)info + 12) & 0x40) != 0)
    dst << "[r" << dst_id << "]";
  else
    dst << "r" << dst_id;

  return dst.str();
}

int call_handler(FILE *stream, const struct printf_info *info,
                const void *const *args) {
  string cond;
  int addr = info->width;
  int reg_id = info->prec;

  if ((*((char *)info + 12) & 0x20) != 0)
    cond = "< 0";
  else if ((*((char *)info + 12) & 0x40) != 0)
    cond = "> 0";
  else if (info->pad == 48)
    cond = "== 0";

  if (cond.empty())
    printf("call 0x%04x\n", addr, cond.c_str());
  else
    printf("call 0x%04x, r%d %s\n", addr, reg_id, cond.c_str());
  return 0;
}

int mov_handler(FILE *stream, const struct printf_info *info,
                const void *const *args) {
  string src = parse_src(info);
  string dst = parse_dst(info);
  printf("mov %s, %s\n", dst.c_str(), src.c_str());
  return 0;
}

int add_handler(FILE *stream, const struct printf_info *info,
                const void *const *args) {
  string src = parse_src(info);
  string dst = parse_dst(info);
  printf("add %s, %s\n", dst.c_str(), src.c_str());
  return 0;
}

int sub_handler(FILE *stream, const struct printf_info *info,
                const void *const *args) {
  string src = parse_src(info);
  string dst = parse_dst(info);
  printf("sub %s, %s\n", dst.c_str(), src.c_str());
  return 0;
}

int mul_handler(FILE *stream, const struct printf_info *info,
                const void *const *args) {
  string src = parse_src(info);
  string dst = parse_dst(info);
  printf("mul %s, %s\n", dst.c_str(), src.c_str());
  return 0;
}

int div_handler(FILE *stream, const struct printf_info *info,
                const void *const *args) {
  string src = parse_src(info);
  string dst = parse_dst(info);
  printf("div %s, %s\n", dst.c_str(), src.c_str());
  return 0;
}

int mod_handler(FILE *stream, const struct printf_info *info,
                const void *const *args) {
  string src = parse_src(info);
  string dst = parse_dst(info);
  printf("mod %s, %s\n", dst.c_str(), src.c_str());
  return 0;
}

int shl_handler(FILE *stream, const struct printf_info *info,
                const void *const *args) {
  string src = parse_src(info);
  string dst = parse_dst(info);
  printf("shl %s, %s\n", dst.c_str(), src.c_str());
  return 0;
}

int shr_handler(FILE *stream, const struct printf_info *info,
                const void *const *args) {
  string src = parse_src(info);
  string dst = parse_dst(info);
  printf("shr %s, %s\n", dst.c_str(), src.c_str());
  return 0;
}

int xor_handler(FILE *stream, const struct printf_info *info,
                const void *const *args) {
  string src = parse_src(info);
  string dst = parse_dst(info);
  printf("xor %s, %s\n", dst.c_str(), src.c_str());
  return 0;
}

int and_handler(FILE *stream, const struct printf_info *info,
                const void *const *args) {
  string src = parse_src(info);
  string dst = parse_dst(info);
  printf("and %s, %s\n", dst.c_str(), src.c_str());
  return 0;
}

int or_handler(FILE *stream, const struct printf_info *info,
               const void *const *args) {
  string src = parse_src(info);
  string dst = parse_dst(info);
  printf("or %s, %s\n", dst.c_str(), src.c_str());
  return 0;
}

int dummy_arginfo(const struct printf_info *info, size_t n, int *argtypes) {
  return 0;
}

void register_conv_specs() {
  // register_printf_function('F', print_flag, dummy_arginfo);
  register_printf_function('C', call_handler, dummy_arginfo);
  register_printf_function('M', mov_handler, dummy_arginfo);
  register_printf_function('S', add_handler, dummy_arginfo);
  register_printf_function('O', sub_handler, dummy_arginfo);
  register_printf_function('X', mul_handler, dummy_arginfo);
  register_printf_function('V', div_handler, dummy_arginfo);
  register_printf_function('N', mod_handler, dummy_arginfo);
  register_printf_function('L', shl_handler, dummy_arginfo);
  register_printf_function('R', shr_handler, dummy_arginfo);
  register_printf_function('E', xor_handler, dummy_arginfo);
  register_printf_function('I', and_handler, dummy_arginfo);
  register_printf_function('U', or_handler, dummy_arginfo);
}

void disassemble() {
  char temp[256];
  char *code_end = code + sizeof(code);
  char *addr = (char *) memchr(code, '%', sizeof(code));

  while (addr) {
    char *end = strchr(addr + 1, '%');
    // Clear temp before using it.
    memset(temp, 0, sizeof(temp));
    if (end)
      strncpy(temp, addr, end - addr);
    else
      strcpy(temp, addr);

    // Trigger the handler
    if (!strstr(temp, "%s")) {
      printf("0x%04x: ", addr - code);
      printf(temp);
    }
    
    // This is the final format-specifier before the null byte. Since null byte
    // will stop the execution flow, put a ret instruction here.
    if (!end)
      printf("0x%04x: ret\n\n", addr + strlen(addr) - code);
    addr = (char *) memchr(addr + 1, '%', code_end - addr - 1); 
  }
}

void decrypt() {
  for (int addr = 0xc8; addr < 0x6fc; ++addr)
    code[addr] ^= 'T';
}

void read_code() {
  ifstream fin("memory.bin", ios::binary);
  fin.seekg(0, ios_base::end);
  streampos file_size = fin.tellg();
  fin.seekg(0, ios_base::beg);
  fin.read(code, file_size);
}

int main() {
  register_conv_specs();
  read_code();
  decrypt();
  disassemble();
  return 0;
} 
```

## 0x02 Solution

Let's start with checking the decrypted code at `0xc8`:

```nasm
0x00c8: mov r4, 0x1388
0x00d2: mov r0, 0x3390
0x00dd: call 0x0151
0x00e2: mov r0, 0x0
0x00e9: call 0x01f4
0x00ee: call 0x04ee
0x00f4: call 0x028d, r0 == 0
0x00fc: ret
```

The function at `0x028d`, basically calculates and puts the flag to `0x1800`.
However, the flag is calculated by some xor operations which includes the city
buffer. Thus, the first goal is to calculate the expected city value.

It is logical to assume that `r0 == 0` checks whether the city name is correct.

Let's check the `0x04ee` function:

```nasm
0x04ee: mov r0, 0x0
0x04f5: mov r1, 0x0
0x04fc: add r1, 0x1194
0x0506: mov r1, [r1]
0x050c: mov r2, 0x0
0x0513: add r2, 0x51eddb21
0x0523: add r2, 0x648c4a88
0x0533: add r2, 0x4355a74c
0x0543: xor r1, r2
0x0549: or r0, r1
0x054f: mov r1, 0x4
0x0556: add r1, 0x1194
0x0560: mov r1, [r1]
0x0566: mov r2, 0x0
0x056d: add r2, 0x32333645
0x057c: add r2, 0x58728e64
0x058c: xor r1, r2
0x0592: or r0, r1
...
```

This function checks buffer at `0x1194`, it must have been set using the city
name. Now, let's investigate the previous `0x01f4` call:

```nasm
0x01f4: mov r2, r0
0x01fa: add r2, 0x1000
0x0204: mov r4, [r2]
0x020a: and r4, 0xff
0x0213: call 0x021c, r4 > 0
0x021b: ret

0x021c: mov r2, r0
0x0222: mul r2, 0x2
0x0229: add r2, 0x1388
0x0233: mov r2, [r2]
0x0239: and r2, 0xff
0x0242: xor r4, r2
0x0248: add r0, 0x1
0x024f: mov r2, r0
0x0255: call 0x01d6
0x025a: add r4, r0
0x0260: and r4, 0xff
0x0269: mov r0, r2
0x026f: sub r2, 0x1
0x0276: add r2, 0x1194
0x0280: mov [r2], r4
0x0287: call 0x01f4
0x028c: ret
```

This code iterates over the characters of the city, xors them using another
buffer located at `0x1388`, adds return value of `func_001d6(i + 1)` for `ith`
character and stores the result in `0x1194 + i`.

The buffer at `0x1388` is initialized with `call 0x0151` and it does not depend
on the city buffer. Thus, we can call `func_0151` to initialize it.

Now, we can translate these functions to C++ and calculate the city value:

```cpp
string find_city() {
  string city;
  // Fill mem[0x1388]
  r4 = 0x1388;
  r0 = 0x3390;
  func_0151();

  int hashes[] = {
    0x51eddb21 + 0x648c4a88 + 0x4355a74c,
    0x32333645 + 0x58728e64,
    0x6f57a0a3,
    0x22d9bbcc + 0x569fcabc,
    0xd531548,
    0x74c2318e + 0x7233f6a3,
    0x6d12a1c5 + 0x6c3422b6 + 0xf213d9a,
  };

  for (int i = 0; i < sizeof(hashes); ++i) {
    r0 = i + 1;
    func_01d6();
    char c = *((char *) hashes + i) - r0;
    c ^= mem[0x1388 + 2 * i]; 
    city += c;
  }
  return city;
}
```

At this point, we can simply get the flag by running the original binary and
entering the expected city. However, it can also be calculated in a similar way:

```cpp
string find_flag(const string &city) {
  int tmp[8] = {};
  int *p_city = (int *) city.c_str();
  int key = 0x75bcd15;
  int hashes[] = {
    0x3278f102, 0x560aa747, 0x3e6fd176,
    0x156d86fa + 0x66c93320,
    0xe5dbc23, 0xd3f894c, 0x324fe212
  };
  int size = sizeof(hashes) / sizeof(hashes[0]);
  for (int i = 0; i < size; ++i) {
    key ^= p_city[i];
    tmp[i] = hashes[i] ^ key;
  }
  string flag((char *) tmp);
  return flag;
}
```

Here is the full C++ source of the solution:

```cpp
#include <stdio.h>
#include <string.h>

#include <iostream>
#include <string>

using namespace std;

void func_01ac();
void func_01d6();
void func_021c();

int r0, r1, r2, r3, r4;
char mem[8192];

void write32(int addr, int value) {
  printf("write [0x%04x] <= 0x08%x\n", addr, value);
  *(int *)(&mem[addr]) = value;
}

int read32(int addr) {
  return *(int *)(&mem[addr]);
}

void func_00fd() {
  r1 = 0;
}

void func_0105() {
  r3 = r0;
  r3 %= r2;
  if (r3 == 0)
    func_00fd();
  r2 += 1;
  r3 = r2;
  r3 *= r3;
  r3 -= r0;
  r3 -= 0x1;
  if (r3 < 0)
    func_0105();
}

void func_0142() {
  write32(r4, r0);
  r4 += 2;
}

void func_0151() {
  r1 = 0x1;
  r2 = 0x2;
  func_0105();
  if (r1 > 0)
    func_0142();
  r0 += 1;
  r1 = 0x3520;
  r1 -= r0;
  if (r1 > 0)
    func_0151();
}

void func_018d() {
  r0 = 0;
}

void func_0195() {
  r0 /= 2;
}

void func_019d() {
  r0 *= 3;
  r0 += 1;
}

void func_01ac() {
  r1 = r0;
  r1 %= 2;
  if (r1 == 0)
    func_0195();
  if (r1 > 0)
    func_019d();
  func_01d6();
  r0 += 1;
}

void func_01d6() {
  r1 = r0;
  r1 -= 1;
  if (r1 == 0)
    func_018d();
  if (r1 > 0)
    func_01ac();
}

void func_01f4() {
  r2 = r0;
  r2 += 0x1000;
  r4 = read32(r2);
  r4 &= 0xff;
  if (r4 > 0) 
    func_021c();
}

void func_021c() {
  r2 = r0;
  r2 *= 2;
  r2 += 0x1388;
  r2 = read32(r2);
  r2 &= 0xff;
  r4 ^= r2;
  r0 += 1;
  r2 = r0;
  func_01d6();
  r4 += r0;
  r4 &= 0xff;
  r0 = r2;
  r2 -= 1;
  r2 += 0x1194;
  write32(r2, r4);
  func_01f4();
}

void func_028d() {
  r0 = 0x75bcd15;
  r1 = 0;
  r1 += 0x1000;
  r1 = read32(r1);
  r0 ^= r1;
  r2 = 0;
  r2 += 0x3278f102;
  r2 ^= r0;
  r1 = 0;
  r1 += 0x1800;
  write32(r1, r2);
  r1 = 0x4;
  r1 += 0x1000;
  r1 = read32(r1);
  r0 ^= r1;
  r2 = 0;
  r2 += 0x560aa747;
  r2 ^= r0;
  r1 = 0x4;
  r1 += 0x1800;
  write32(r1, r2);
  r1 = 0x8;
  r1 += 0x1000;
  r1 = read32(r1);
  r0 ^= r1;
  r2 = 0;
  r2 += 0x3e6fd176;
  r2 ^= r0;
  r1 = 0x8;
  r1 += 0x1800;
  write32(r1, r2); 
  r1 = 0xc;
  r1 += 0x1000;
  r1 = read32(r1);
  r0 ^= r1;
  r2 = 0;
  r2 += 0x156d86fa;
  r2 += 0x66c93320;
  r2 ^= r0;
  r1 = 0xc;
  r1 += 0x1800;
  write32(r1, r2);
  r1 = 0x10;
  r1 += 0x1000;
  r1 = read32(r1);
  r0 ^= r1;
  r2 = 0;
  r2 += 0xe5dbc23;
  r2 ^= r0;
  r1 = 0x10;
  r1 += 0x1800;
  write32(r1, r2);
  r1 = 0x14;
  r1 += 0x1000;
  r1 = read32(r1);
  r0 ^= r1;
  r2 = 0;
  r2 += 0xd3f894c;
  r2 ^= r0;
  r1 = 0x14;
  r1 += 0x1800;
  write32(r1, r2);
  r1 = 0x18;
  r1 += 0x1000;
  r1 = read32(r1);
  r0 ^= r1;
  r2 = 0;
  r2 += 0x324fe212;
  r2 ^= r0;
  r1 = 0x18;
  r1 += 0x1800;
  write32(r1, r2);
}

void func_04ee() {
  r0 = 0;
  r1 = 0;
  r1 += 0x1194;
  r1 = read32(r1);
  r2 = 0;
  r2 += 0x51eddb21;
  r2 += 0x648c4a88;
  r2 += 0x4355a74c;
  r1 ^= r2;
  r0 |= r1;
  r1 = 0x4;
  r1 += 0x1194;
  r1 = read32(r1);
  r2 = 0;
  r2 += 0x32333645;
  r2 += 0x58728e64;
  r1 ^= r2;
  r0 |= r1;
  r1 = 0x8;
  r1 += 0x1194;
  r1 = read32(r1);
  r2 = 0;
  r2 += 0x6f57a0a3;
  r1 ^= r2;
  r0 |= r1;
  r1 = 0xc;
  r1 += 0x1194;
  r1 = read32(r1);
  r2 = 0;
  r2 += 0x22d9bbcc;
  r2 += 0x569fcabc;
  r1 ^= r2;
  r0 |= r1;
  r1 = 0x10;
  r1 += 0x1194;
  r1 = read32(r1);
  r2 = 0;
  r2 += 0xd531548;
  r1 ^= r2;
  r0 |= r1;
  r1 = 0x14;
  r1 += 0x1194;
  r1 = read32(r1);
  r2 = 0;
  r2 += 0x74c2318e;
  r2 += 0x7233f6a3;
  r1 ^= r2;
  r0 |= r1;
  r1 = 0x18; 
  r1 += 0x1194;
  r1 = read32(r1);
  r2 = 0;
  r2 += 0x6d12a1c5;
  r2 += 0x6c3422b6;
  r2 += 0xf213d9a;
  r1 ^= r2;
  r0 |= r1;
}

void func_00c8() {
  r4 = 0x1388;
  r0 = 0x3390;
  func_0151();
  r0 = 0x0;
  func_01f4();
  func_04ee();
  if (r0 == 0)
    func_028d();
}

string find_city() {
  string city;
  // Fill mem[0x1388]
  r4 = 0x1388;
  r0 = 0x3390;
  func_0151();

  int hashes[] = {
    0x51eddb21 + 0x648c4a88 + 0x4355a74c,
    0x32333645 + 0x58728e64,
    0x6f57a0a3,
    0x22d9bbcc + 0x569fcabc,
    0xd531548,
    0x74c2318e + 0x7233f6a3,
    0x6d12a1c5 + 0x6c3422b6 + 0xf213d9a,
  };

  for (int i = 0; i < sizeof(hashes); ++i) {
    r0 = i + 1;
    func_01d6();
    char c = *((char *) hashes + i) - r0;
    c ^= mem[0x1388 + 2 * i]; 
    city += c;
  }
  return city;
}

string find_flag(const string &city) {
  int tmp[8] = {};
  int *p_city = (int *) city.c_str();
  int key = 0x75bcd15;
  int hashes[] = {
    0x3278f102, 0x560aa747, 0x3e6fd176,
    0x156d86fa + 0x66c93320,
    0xe5dbc23, 0xd3f894c, 0x324fe212
  };
  int size = sizeof(hashes) / sizeof(hashes[0]);
  for (int i = 0; i < size; ++i) {
    key ^= p_city[i];
    tmp[i] = hashes[i] ^ key;
  }
  string flag((char *) tmp);
  return flag;
}

int main() {
  // strcpy(&mem[0x1000], "TheNewFlagHillsByTheCtfWoods");
  // func_00c8();
  string city = find_city();
  cout << "City: " << city << endl;
  string flag = find_flag(city);
  cout << "Flag: " << flag << endl;
  return 0;
} 
```
