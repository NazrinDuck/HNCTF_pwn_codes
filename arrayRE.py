from pwn import *
from LibcSearcher import *

context(arch="amd64", os="linux", log_level="debug")
context.terminal = ["tmux", "split", "-h"]
# context(arch="amd64",os="linux",log_level="debug")
binary = "./arrayRE/arrayRE"
libc = "../../Libcs/libc.so.6_3"

rop = ROP(binary)
elf = ELF(binary)

libc_elf = ELF(libc)
# libc_dll = cdll.LoadLibrary(libc)


local = 1

ip, port = "61.147.171.105", 23430
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
# dbg(p)
p.sendline(b"aaaa")
passwd = "831654239123423452610584"
input = ""

for i in range(len(passwd) - 1, 0, -1):
    pre = ord(passwd[i - 1])
    ch = passwd[i]

    tmp0 = (35 * (pre - 48) + 18 * (pre + i - 1 - 48) + 2) % 10

    tmp1 = ord(ch) - 48
    tmp2 = tmp1 - 3 - tmp0
    fini = tmp2 + 48

    print("No." + str(i) + ":" + str(tmp0))
    print("No." + str(i) + ":" + str(tmp1))
    print("No." + str(i) + ":" + str(fini))

    while fini <= 47 or fini > 57:
        tmp1 += 10
        tmp2 = tmp1 - 3 - tmp0
        fini = tmp2 + 48
        # print("No." + str(i) + ":" + str(fini))

    """
    while tmp2 < 0:
        tmp2 += 10

    tmp3 = tmp2 + 48 * (35 + 18) - 18 * i - 2
    while tmp3 % (35 + 18) != 0:
        tmp3 += 10
    fini = chr(int(tmp3 / (35 + 18)))

    if ord(fini) <= 47 or ord(fini) > 57:
        while tmp3 % (35 + 18) != 0:
            tmp3 -= 10
        fini = chr(int(tmp3 / (35 + 18)))

    while ord(fini) <= 47 or ord(fini) > 57:
        tmp2 += 10
        tmp3 = tmp2 + 48 * (35 + 18) - 18 * i - 2
        while tmp3 % (35 + 18) != 0:
            tmp3 += 10
        fini = chr(int(tmp3 / (35 + 18)))

        if ord(fini) <= 47 or ord(fini) > 57:
            while tmp3 % (35 + 18) != 0:
                tmp3 -= 10
            fini = chr(int(tmp3 / (35 + 18)))

    pre = fini
    """
    input += chr(fini)
    print("No." + str(i) + ":" + str(tmp2))

print(input[::-1])


payload = ("8" + input[::-1]).encode()
# dbg(p)
p.sendline(payload)


p.interactive()
