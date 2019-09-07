""" It's hexdump but with inline comments """

import sys
import struct
from gfx import Hexdump, Annotation

def unicode_escape(x):
    return repr(x)[2:-1]

def generate_annotations(data):
    """ Generate a dictionary of annotations for some ELF data

        Returns:
            mapping between indices and a list of annotations
    """
    annotations = []
    color_wheel = [
        "red",
        "green",
        "yellow",
        "blue",
        "magenta",
        "cyan"
    ]
    color_i = 0
    def add_annotation(sb, eb, msg):
        nonlocal color_i
        annotations.append(Annotation(sb, eb, msg, color_wheel[color_i]))
        color_i = (color_i + 1) % len(color_wheel)

    # ---------- BEGIN ACTUAL PARSING --------------

    # //-------- ELF HEADER --------------

    # Magic number
    msg = "Magic Number: " + unicode_escape(data[0x00:0x04])
    add_annotation(0x00, 0x04, msg)

    # Bit representation
    ei_class = data[0x04]
    if ei_class == 1:
        msg = "Bit: 32-bit"
    elif ei_class == 2:
        msg = "Bit: 64-bit"
    else:
        msg = "Bit: UNKNOWN"
    add_annotation(0x04, 0x05, msg)

    # Endianness
    ei_data = data[0x05]
    if ei_class == 1:
        msg = "Endianness: little"
    elif ei_class == 2:
        msg = "Endianness: big"
    else:
        msg = "Endianness: UNKNOWN"
    add_annotation(0x05, 0x06, msg)

    # ELF version
    ei_version = data[0x06]
    msg = "ELF version: " + unicode_escape(data[0x06:0x07])
    add_annotation(0x06, 0x07, msg)

    # ABI
    ei_osabi = data[0x07]
    msg = "ABI: " + unicode_escape(data[0x07:0x08])
    add_annotation(0x07, 0x08, msg)

    # ABI version
    ei_abiversion = data[0x08]
    msg = "ABI version: " + unicode_escape(data[0x08:0x09])
    add_annotation(0x08, 0x09, msg)

    # Object file type
    e_type = data[0x10:0x12]
    e_type = struct.unpack("<H", e_type)[0]
    if e_type == 0x00:
        msg = "Object file type: ET_NONE"
    elif e_type == 0x01:
        msg = "Object file type: ET_REL"
    elif e_type == 0x02:
        msg = "Object file type: ET_EXEC"
    elif e_type == 0x03:
        msg = "Object file type: ET_DYN"
    elif e_type == 0x04:
        msg = "Object file type: ET_CORE"
    elif e_type == 0xfe00:
        msg = "Object file type: ET_LOOS"
    elif e_type == 0xfeff:
        msg = "Object file type: ET_HIOS"
    elif e_type == 0xff00:
        msg = "Object file type: ET_LOPROC"
    elif e_type == 0xffff:
        msg = "Object file type: ET_HIPROC"
    else:
        msg = "Object file type: UNKNOWN"
    add_annotation(0x10, 0x12, msg)

    # Target instruction set architecture
    e_machine = data[0x12:0x14]
    e_machine = struct.unpack("<H", e_machine)[0]
    if e_machine == 0x00:
        msg = "ISA: No specified set"
    elif e_machine == 0x02:
        msg = "ISA: SPARC"
    elif e_machine == 0x03:
        msg = "ISA: x86"
    elif e_machine == 0x08:
        msg = "ISA: MIPS"
    elif e_machine == 0x14:
        msg = "ISA: PowerPC"
    elif e_machine == 0x16:
        msg = "ISA: S390"
    elif e_machine == 0x28:
        msg = "ISA: ARM"
    elif e_machine == 0x2A:
        msg = "ISA: SuperH"
    elif e_machine == 0x32:
        msg = "ISA: IA-64"
    elif e_machine == 0x3E:
        msg = "ISA: x86-64"
    elif e_machine == 0xB7:
        msg = "ISA: AArch64"
    elif e_machine == 0xF3:
        msg = "ISA: RISC-V"
    else:
        msg = "ISA: UNKNOWN"
    add_annotation(0x12, 0x14, msg)

    # Entry point
    if ei_class == 1:
        e_entry = data[0x18:0x18+4]
        e_entry = struct.unpack("<L", e_entry)[0]
        msg = "Entry point: " + hex(e_entry)
        add_annotation(0x18, 0x18+4, msg)
    elif ei_class == 2:
        e_entry = data[0x18:0x18+8]
        e_entry = struct.unpack("<Q", e_entry)[0]
        msg = "Entry point: " + hex(e_entry)
        add_annotation(0x18, 0x18+8, msg)

    # Program header table start
    if ei_class == 1:
        e_phoff = data[0x1C:0x1C+4]
        e_phoff = struct.unpack("<L", e_phoff)[0]
        msg = "Program header offset: " + hex(e_phoff)
        add_annotation(0x1C, 0x1C+4, msg)
    elif ei_class == 2:
        e_phoff = data[0x20:0x20+8]
        e_phoff = struct.unpack("<Q", e_phoff)[0]
        msg = "Program header offset: " + hex(e_phoff)
        add_annotation(0x20, 0x20+8, msg)

    # Section header table start
    if ei_class == 1:
        e_shoff = data[0x20:0x20+4]
        e_shoff = struct.unpack("<L", e_shoff)[0]
        msg = "Section header offset: " + hex(e_shoff)
        add_annotation(0x20, 0x20+4, msg)
    elif ei_class == 2:
        e_shoff = data[0x28:0x28+8]
        e_shoff = struct.unpack("<Q", e_shoff)[0]
        msg = "Section header offset: " + hex(e_shoff)
        add_annotation(0x28, 0x28+8, msg)

    # Program header entry size
    if ei_class == 1:
        e_phentsize = data[0x2A:0x2A+2]
        e_phentsize = struct.unpack("<H", e_phentsize)[0]
        msg = "Program header entry size: " + hex(e_phentsize)
        add_annotation(0x2A, 0x2A+2, msg)
    elif ei_class == 2:
        e_phentsize = data[0x36:0x36+2]
        e_phentsize = struct.unpack("<H", e_phentsize)[0]
        msg = "Program header entry size: " + hex(e_phentsize)
        add_annotation(0x36, 0x36+2, msg)

    # Program header entry count
    if ei_class == 1:
        e_phnum = data[0x2C:0x2C+2]
        e_phnum = struct.unpack("<H", e_phnum)[0]
        msg = "Program header entries: " + hex(e_phnum)
        add_annotation(0x2C, 0x2C+2, msg)
    elif ei_class == 2:
        e_phnum = data[0x38:0x38+2]
        e_phnum = struct.unpack("<H", e_phnum)[0]
        msg = "Program header entries: " + str(e_phnum)
        add_annotation(0x38, 0x38+2, msg)

    # Section header entry size
    if ei_class == 1:
        e_shentsize = data[0x2E:0x2E+2]
        e_shentsize = struct.unpack("<H", e_shentsize)[0]
        msg = "Section header entry size: " + hex(e_phentsize)
        add_annotation(0x2E, 0x2E+2, msg)
    elif ei_class == 2:
        e_shentsize = data[0x3A:0x3A+2]
        e_shentsize = struct.unpack("<H", e_shentsize)[0]
        msg = "Section header entry size: " + hex(e_shentsize)
        add_annotation(0x3A, 0x3A+2, msg)

    # Section header entry count
    if ei_class == 1:
        e_shnum = data[0x30:0x30+2]
        e_shnum = struct.unpack("<H", e_shnum)[0]
        msg = "Section header entries: " + hex(e_shnum)
        add_annotation(0x30, 0x30+2, msg)
    elif ei_class == 2:
        e_shnum = data[0x3C:0x3C+2]
        e_shnum = struct.unpack("<H", e_shnum)[0]
        msg = "Section header entries: " + str(e_shnum)
        add_annotation(0x3C, 0x3C+2, msg)

    # Index of section header table entry that contains section names
    if ei_class == 1:
        e_shstrndx = data[0x32:0x32+2]
        e_shstrndx = struct.unpack("<H", e_shstrndx)[0]
        msg = "Section names section index: " + hex(e_shstrndx)
        add_annotation(0x32, 0x32+2, msg)
    elif ei_class == 2:
        e_shstrndx = data[0x3E:0x3E+2]
        e_shstrndx = struct.unpack("<H", e_shstrndx)[0]
        msg = "Section names section index: " + str(e_shstrndx)
        add_annotation(0x3E, 0x3E+2, msg)

    # //-------- PROGRAM HEADER --------------
    for i in range(e_phnum):
        start = e_phoff + i * e_phentsize
        end = e_phoff + (i + 1) * e_phentsize
        type_i = data[start:start+4]
        type_i = struct.unpack("<L", type_i)[0]
        types = {
                0x00000000: "PT_NULL",
                0x00000001: "PT_LOAD",
                0x00000002: "PT_DYNAMIC",
                0x00000003: "PT_INTERP",
                0x00000004: "PT_NOTE",
                0x00000005: "PT_SHLIB",
                0x00000006: "PT_PHDR",
                0x00000007: "PT_TLS",
                0x60000000: "PT_LOOS",
                0x6FFFFFFF: "PT_HIOS",
                0x70000000: "PT_LOPROC",
                0x7FFFFFFF: "PT_HIPROC"
        }
        if type_i in types:
            type_ = types[type_i]
        else:
            type_ = "UNKNOWN"

        msg = "Segment {0:d} ({1})".format(i, type_)
        add_annotation(start, end, msg)

    # //-------- SECTION HEADER --------------
    for i in range(e_shnum):
        start = e_shoff + i * e_shentsize
        end = e_shoff + (i + 1) * e_shentsize
        type_i = data[start:start+4]
        type_i = struct.unpack("<L", type_i)[0]
        types = {
                0x0: "SHT_NULL",
                0x1: "SHT_PROGBITS",
                0x2: "SHT_SYMTAB",
                0x3: "SHT_STRTAB",
                0x4: "SHT_RELA",
                0x5: "SHT_HASH",
                0x6: "SHT_DYNAMIC",
                0x7: "SHT_NOTE",
                0x8: "SHT_NOBITS",
                0x9: "SHT_REL",
                0x0A: "SHT_SHLIB",
                0x0B: "SHT_DYNSYM",
                0x0E: "SHT_INIT_ARRAY",
                0x0F: "SHT_FINI_ARRAY",
                0x10: "SHT_PREINIT_ARRAY",
                0x11: "SHT_GROUP",
                0x12: "SHT_SYMTAB_SHNDX",
                0x13: "SHT_NUM",
        }
        if type_i in types:
            type_ = types[type_i]
        else:
            type_ = "UNKNOWN"

        msg = "Section {0:d} ({1})".format(i, type_)

        add_annotation(start, end, msg)



    return annotations

def hexdump_file(fname):
    # Read binary data
    with open(fname, "rb") as f:
        data = f.read()

    # Create a hexdump object
    h = Hexdump.init_from_dump(data)

    # Generate annotations on this dump
    h.annotations = generate_annotations(data)

    # Print hexdump
    print(h)

if __name__ == "__main__":
    fname = sys.argv[1]
    hexdump_file(fname)
