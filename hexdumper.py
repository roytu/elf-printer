""" It's hexdump but with inline comments """

import sys
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

    # Parse ELF header

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
