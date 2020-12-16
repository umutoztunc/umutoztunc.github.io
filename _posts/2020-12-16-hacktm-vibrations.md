---
layout: post
title: "HackTM CTF Finals 2020 / Vibrations"
permalink: /hacktm-finals-2020-vibrations
---

The binary creates two map objects and calls `main_aa`, `main_bb`, and `main__XYZ_z` functions respectively.
```nasm
.text:00000000004A41C0 call    main_aa
.text:00000000004A41C5 lea     rax, [rsp+1A0h+obj]
.text:00000000004A41CD mov     [rsp+1A0h+var_1A0], rax
.text:00000000004A41D1 call    main_bb
.text:00000000004A41D6 lea     rax, [rsp+1A0h+obj]
.text:00000000004A41DE mov     [rsp+1A0h+var_1A0], rax
.text:00000000004A41E2 lea     rax, [rsp+1A0h+input]
.text:00000000004A41EA mov     [rsp+1A0h+var_198], rax
.text:00000000004A41EF call    main__XYZ_z
.text:00000000004A41F4 cmp     byte ptr [rsp+1A0h+var_190], 0
.text:00000000004A41F9 jz      loc_4A4387
```

`main_aa` function provides an object that is used to access the maps and local variables that are defined in `main_main` function. It is more like a `this` variable, but I did not investigate what it is and how it is created.

If we look inside the `main_bb` function we see a lot of functions calls to `main__XYZ_b` as follows:
```nasm
.text:00000000004A2057 mov     [rsp+38h+var_8], rbp
.text:00000000004A205C lea     rbp, [rsp+38h+var_8]
.text:00000000004A2061 mov     rax, [rsp+38h+obj]
.text:00000000004A2066 mov     [rsp+38h+var_38], rax
.text:00000000004A206A mov     [rsp+38h+var_30], 7Eh
.text:00000000004A2073 lea     rcx, aC         ; "C"
.text:00000000004A207A mov     [rsp+38h+var_28], rcx
.text:00000000004A207F mov     [rsp+38h+var_20], 1
.text:00000000004A2088 mov     [rsp+38h+var_18], 7Fh
.text:00000000004A2091 call    main__XYZ_b
```

Let's analyze the `main__XYZ_b` function to understand the purpose of these calls:
```nasm
.text:00000000004A4506 mov     rax, [rsp+50h+key] ; key
.text:00000000004A450B mov     [rsp+50h+var_20], rax
.text:00000000004A4510 mov     rax, [rsp+50h+str_key] ; key_str
.text:00000000004A4515 mov     [rsp+50h+var_18], rax
.text:00000000004A451A mov     rax, [rsp+50h+str_key_len] ; key_len
.text:00000000004A451F mov     [rsp+50h+var_10], rax
.text:00000000004A4524 mov     rax, [rsp+50h+obj]
.text:00000000004A4529 mov     rax, [rax+40h]
.text:00000000004A452D lea     rcx, unk_4B3C00
.text:00000000004A4534 mov     [rsp+50h+var_50], rcx ; maptype
.text:00000000004A4538 mov     [rsp+50h+var_48], rax ; map
.text:00000000004A453D lea     rax, [rsp+50h+var_20]
.text:00000000004A4542 mov     [rsp+50h+var_40], rax ; key
.text:00000000004A4547 call    runtime_mapassign
.text:00000000004A454C mov     rax, [rsp+50h+var_38]
.text:00000000004A4551 mov     rcx, [rsp+50h+value]
.text:00000000004A4556 mov     [rax], rcx      ; map[from, char] = to
```

This code snippet basically maps one number to another via a char. For instance, the example I used above maps 0x7E to 0x7F via "C". After checking the parameters of other calls, I noticed that the numbers are always consecutive.

Now that we know what `main_bb` does, we can take a look at `main__XYZ_z`. This function takes our input as one of its parameters.

It loops through each character of our input and does the following:
```nasm
.text:00000000004A468F                 mov     [rsp+68h+var_38], rdx
.text:00000000004A4694                 lea     rax, [rsp+68h+var_3C]
.text:00000000004A4699                 mov     [rsp+68h+var_68], rax
.text:00000000004A469D                 movsxd  rax, ebx        ; char
.text:00000000004A46A0                 mov     [rsp+68h+var_60], rax
.text:00000000004A46A5                 call    runtime_intstring
.text:00000000004A46AA                 mov     rax, [rsp+68h+var_58]
.text:00000000004A46AF                 mov     rcx, [rsp+68h+var_50]
.text:00000000004A46B4                 mov     rdx, [rsp+68h+obj]
.text:00000000004A46B9                 mov     rbx, [rdx+8]    ; position
.text:00000000004A46BD                 mov     [rsp+68h+var_20], rbx
.text:00000000004A46C2                 mov     [rsp+68h+var_18], rax
.text:00000000004A46C7                 mov     [rsp+68h+var_10], rcx
.text:00000000004A46CC                 mov     rax, [rdx+40h]  ; map
.text:00000000004A46D0                 lea     rcx, unk_4B3C00
.text:00000000004A46D7                 mov     [rsp+68h+var_68], rcx
.text:00000000004A46DB                 mov     [rsp+68h+var_60], rax
.text:00000000004A46E0                 lea     rax, [rsp+68h+var_20]
.text:00000000004A46E5                 mov     [rsp+68h+var_58], rax
.text:00000000004A46EA                 call    runtime_mapaccess2
.text:00000000004A46EF                 mov     rax, [rsp+68h+var_50]
.text:00000000004A46F4                 mov     rax, [rax]
.text:00000000004A46F7                 cmp     byte ptr [rsp+68h+var_48], 0
.text:00000000004A46FC                 jz      short loc_4A470C
.text:00000000004A46FE key exists
.text:00000000004A46FE                 mov     rcx, [rsp+68h+obj]
.text:00000000004A4703                 mov     [rcx+8], rax    ; position = map[position, char]
.text:00000000004A4707                 jmp     loc_4A465B
.text:00000000004A470C ; ---------------------------------------------------------------------------
.text:00000000004A470C key does not exist
.text:00000000004A470C
.text:00000000004A470C loc_4A470C:                             ; CODE XREF: main__XYZ_z+DC↑j
.text:00000000004A470C                 mov     rcx, [rsp+68h+obj]
.text:00000000004A4711                 jmp     loc_4A465B
```

This code tries to get the next position from the map we found earlier by using the current position and current character of the input. It can be seen by debugging that the staring position is 0, which is probably set in `main_main` or `main_aa`.

After the loop, it calls `main__XYZ_x` which just checks if our position is the final position which is supposed to be 0x86.

At this point, I decided to write a gdb script to log all calls to `main__XYZ_b` and dump the map to create the correct sequence of characters that leads us from position 0 to 0x86:
```python
#!/usr/bin/env python3
import gdb

gdb.execute('bp 0x4A4480')
gdb.execute('run < /dev/null')

password = ['?'] * 0x86
while True:
    try:
        from_pos = int(gdb.parse_and_eval('*(int *)($rsp + 0x10)'))
        char = chr(gdb.parse_and_eval('**(char **)($rsp + 0x18)'))
        to_pos = int(gdb.parse_and_eval('*(int *)($rsp + 0x28)'))
        password[from_pos] = char
        gdb.execute('continue')
    except:
        break

print(''.join(password))
gdb.execute('quit')
```

After getting the password from the script, I immediately tested it. However, the program slowly printed the password back and crashed with index out of bounds error. 

The program is supposed to print each character back and sleep in between. Then, call `main_c` on the input. I decided to bypass the loop, so that it immediately calls `main_c` instead. In order to achieve that I have patched the following conditional jump.

```nasm
.text:00000000004A4240 loc_4A4240:                             ; CODE XREF: main_main+240↑j
.text:00000000004A4240                 cmp     rcx, rdx
.text:00000000004A4243                 jle     loc_4A4366
```

After patching the conditional jump from `jle` to `jmp`, I was able to run the program and get the flag.
