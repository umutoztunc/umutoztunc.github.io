---
layout: post
title: "HITCON 2020 / Tenet"
permalink: /hitcon-2020-tenet
---

After spending some time on reverse engineering the binary, I got the following decompilation:
```c
__int64 __fastcall main(int argc, char **argv, char **envp)
{
  int current_step; // ebx
  bool has_shellcode_started; // [rsp+1Ah] [rbp-26h]
  bool sysexit_encountered; // [rsp+1Bh] [rbp-25h]
  __WAIT_STATUS stat_loc; // [rsp+1Ch] [rbp-24h]
  int v8; // [rsp+24h] [rbp-1Ch]
  unsigned __int64 v9; // [rsp+28h] [rbp-18h]

  v9 = __readfsqword(0x28u);
  if ( argc != 2 )
    exit(2);
  setbuf(stdout, 0LL);
  pid = fork();
  if ( !pid )
  {                                             // child process only
    ptrace(PTRACE_TRACEME, 0LL, 0LL, 0LL);
    execve(argv[1], 0LL, 0LL);                  // argv[1] is the path of shellcode ELF file.
    failure("execve");
  }
  if ( ptrace(PTRACE_ATTACH, (unsigned int)pid, 0LL, 0LL) )
    err(1, "ptrace");
  LODWORD(stat_loc.__uptr) = 0;
  HIDWORD(stat_loc.__iptr) = waitpid(pid, &stat_loc, WUNTRACED);
  if ( HIDWORD(stat_loc.__iptr) != pid || LOBYTE(stat_loc.__uptr) != 127 )
    failure("the first wait");
  has_shellcode_started = 0;
  sysexit_encountered = 0;
  while ( 1 )
  {
    if ( ptrace(PTRACE_SINGLESTEP, (unsigned int)pid, 0LL, 0LL) )
      err(1, "ptrace", argv);
    HIDWORD(stat_loc.__iptr) = wait((__WAIT_STATUS)&stat_loc);
    if ( !((_QWORD)stat_loc.__uptr & 0x7F) )
      break;
    v8 = (SLODWORD(stat_loc.__uptr) >> 8) & 0xFF;
    if ( v8 != 5 )
      failure2("Child dead unexpectedly.");
    if ( step_count > 4095 )
      failure2("Too many steps.");
    if ( has_shellcode_started != 1 && get_rip_value() == 0xDEAD0080 )
    {
      has_shellcode_started = 1;
      set_cs_and_ss();
      clear_memory();
      write_cookie();
    }
    if ( has_shellcode_started )
    {
      if ( next_nonsyscall_ins() )
      {
        sysexit_encountered = 1;
        break;
      }
      current_step = step_count++;
      nonsyscall_ins_addresses[current_step] = get_rip_value();
    }
  }
  if ( sysexit_encountered != 1 )
    failure2("...?");
  if ( !is_memory_empty() )
    failure2("Please swallow the cookie.");
  execute_steps_backwards();
  if ( !is_cookie_still_there() )
    failure2("You should vomit the cookie out.");
  print_flag();
  return 0LL;
}
```

The ruby script creates an ELF file from our shellcode and passes the file to this program as a parameter. This program uses ptrace to trace our payload and manipulates its memory, registers, etc. Just before our shellcode starts, the tracer clears the memory range `0x2170000-0x2170fff` of the tracee, and writes a random 64-bit value to `0x2170000`. I will refer this value as the `cookie`.

When the code reaches to our shellcode, it starts single-stepping it and logging instruction addresses except for syscall instructions. We are not allowed to step more than 4095 times.

It also expects our shellcode to finish with a `sys_exit` call.

Here how it checks whether our shellcode is succcessful:
1. Clear the memory range `0x2170000-0x2170fff` of tracee.
2. Generate a random `cookie` and write it at `0x2170000`.
3. Single-step shellcode and log all non-syscall instructions' addresses until `sys_exit` is encountered.
4. Check if `0x2170000-0x2170fff` is empty.
5. Execute the logged instructions backwards.
6. Check if `0x2170000` still stores the `cookie`.
7. Print flag.

So, we need to write a shellcode that will clear the `cookie` when executed, and it needs to restore the `cookie` when it is executed backwards.

So far so good, but there is a catch. The ruby script prepends some bytes to our shellcode before creating the ELF payload.

If we look at generated ELF file. We get this:
```nasm
LOAD:00000000DEAD005C main:                                   ; CODE XREF: start↑j
LOAD:00000000DEAD005C                 call    init_chall
LOAD:00000000DEAD0061                 mov     rdi, rsp
LOAD:00000000DEAD0064                 and     rdi, 0FFFFFFFFFFFFF000h
LOAD:00000000DEAD006B                 sub     rdi, 21000h     ; addr
LOAD:00000000DEAD0072                 mov     rsi, 24000h     ; len
LOAD:00000000DEAD0079                 xor     rax, rax
LOAD:00000000DEAD007C                 mov     al, 0Bh
LOAD:00000000DEAD007E                 syscall                 ; LINUX - sys_munmap
LOAD:00000000DEAD0080                 <our shellcode starts here>
```

It calls `sys_munmap` on the stack, just before executing our shellcode. Which means we won't be able to store our `cookie` at stack. Also, if we look at the function `init_chall`:
```nasm
LOAD:00000000DEAD0002 init_chall      proc near               ; CODE XREF: start:main↓p
LOAD:00000000DEAD0002                 push    26h             ; PR_SET_NO_NEW_PRIVS
LOAD:00000000DEAD0004                 pop     rdi             ; option
LOAD:00000000DEAD0005                 push    1
LOAD:00000000DEAD0007                 pop     rsi             ; arg2
LOAD:00000000DEAD0008                 xor     eax, eax
LOAD:00000000DEAD000A                 mov     al, 9Dh
LOAD:00000000DEAD000C                 syscall                 ; LINUX - sys_prctl
LOAD:00000000DEAD000E                 push    16h             ; PR_SET_SECCOMP
LOAD:00000000DEAD0010                 pop     rdi             ; option
LOAD:00000000DEAD0011                 lea     rdx, filter
LOAD:00000000DEAD0018                 push    rdx
LOAD:00000000DEAD0019                 push    6
LOAD:00000000DEAD001B                 mov     rdx, rsp        ; arg3
LOAD:00000000DEAD001E                 push    2               ; SECCOMP_MODE_FILTER
LOAD:00000000DEAD0020                 pop     rsi             ; arg2
LOAD:00000000DEAD0021                 xor     eax, eax
LOAD:00000000DEAD0023                 mov     al, 9Dh
LOAD:00000000DEAD0025                 syscall                 ; LINUX - sys_prctl
LOAD:00000000DEAD0027                 add     rsp, 10h
LOAD:00000000DEAD002B                 retn
LOAD:00000000DEAD002B init_chall      endp
LOAD:00000000DEAD002B
LOAD:00000000DEAD002B ; ---------------------------------------------------------------------------
LOAD:00000000DEAD002C ; struct sock_filter filter
LOAD:00000000DEAD002C filter          sock_filter <20h, 0, 0, 4>
LOAD:00000000DEAD002C                                         ; DATA XREF: init_chall+F↑o
LOAD:00000000DEAD002C                 sock_filter <15h, 0, 2, 0C000003Eh>
LOAD:00000000DEAD002C                 sock_filter <20h, 0, 0, 0>
LOAD:00000000DEAD002C                 sock_filter <15h, 1, 0, 0Bh>
LOAD:00000000DEAD002C                 sock_filter <6, 0, 0, 0>
LOAD:00000000DEAD002C                 sock_filter <6, 0, 0, 7FFF0000h>
```

We see that `PR_SET_NO_NEW_PRIVS` is set to 1, and seccomp is enabled with a user-defined filter.

We can use `seccomp-tools` to dump that filter:
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x02 0xc000003e  if (A != ARCH_X86_64) goto 0004
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x01 0x00 0x0000000b  if (A == munmap) goto 0005
 0004: 0x06 0x00 0x00 0x00000000  return KILL
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

As you can see, we are not allowed to use any syscall other than `sys_munmap`, and we are not allowed to use 32-bit instructions and syscalls.

I was thinking about finding a place to store information and I realized that by logging our instructions, it actually stores information. So, if I write a loop and execute an instruction n times, it has to be executed n times again during the backwards execution. Thus, my idea was to run a loop for each byte of the `cookie`. Each loop will be executed k times where k is the value of the corresponding byte. This way, we can increment a register in the loop and set it to zero afterwards. When it gets executed in reverse order, the register will store the corresponding byte's initial value. Rest is creating the cookie backwards and writing it back to `0x2170000`.

I have talked to [@david942j](//twitter.com/david942j) about it, and he said this wasn't the intended solution. The intended solution applies a similar idea. However, it uses bitwise operations instead of simple increment/decrement operations which results in less steps. The only problem with my solution is that if each k value is large, we might hit the step limit. Still, I had a pretty high success rate in my local environment and I got the flag from the remote server in my first attempt.

Here is my shellcode:
```nasm
mov r12, qword ptr [0x2170000]
mov qword ptr [0x2170000], r12
mov r11, r12
mov r12, r10

loop:
mov r8, r11
and r8, 0xFF
xor r9, r9
add r10, r9
shl r10, 8
loop2:
test r8, r8
jz loop2_end
inc r9
dec r8
jmp loop2
loop2_end:
shr r11, 8
test r11, r11
jnz loop

xor r9, r9
xor r10, r10

mov qword ptr [0x2170000], 0
mov rax, 60
syscall
```
