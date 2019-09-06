
import colored

class Annotation(object):
    def __init__(self, start_byte, end_byte, msg, bgcolor):
        self.start_byte = start_byte
        self.end_byte = end_byte
        self.msg = msg
        self.fgcolor = colored.fg("white")
        self.bgcolor = colored.bg(bgcolor)

    def __str__(self):
        return colored.bg(self.bgcolor) + self.msg + colored.attr("reset")

class Hexdump(object):
    def __init__(self):
        self.hex_bytes = []   # List of bytes (as hex)
        self.annotations = []

    @staticmethod
    def init_from_dump(data):
        """ Initialize a hexdump object from a dump """
        h = Hexdump()
        h.hex_bytes = ["{0:02x}".format(b) for b in data]
        return h

    @staticmethod
    def _find_overlap(a0, a1, b0, b1):
        """ Find overlap between intervals [a0, a1) and [b0, b1)

            Returns:
                [m, n) the interval of overlap (or None)
        """
        if b0 >= a1 or a0 >= b1:
            return None
        else:
            m = max(a0, b0)
            n = min(a1, b1)
            return (m, n)

    def __str__(self):
        """
            We have a list of hex bytes and a list of annotations
            Assume no annotations overlap

            We need to convert this into a list of formatted lines
        """
        BLOCK_SIZE = 16

        # First, create byte blocks
        byte_lines = []
        for i in range(0, len(self.hex_bytes), BLOCK_SIZE):
            block = self.hex_bytes[i:i+BLOCK_SIZE]

            # Go through the annotations and see if there's overlap
            for annotation in self.annotations:
                a0 = annotation.start_byte
                a1 = annotation.end_byte

                # Detect overlap and apply if there is
                overlap = Hexdump._find_overlap(a0, a1, i, i+BLOCK_SIZE)
                if overlap is None:
                    continue
                (m, n) = overlap
                m -= i
                n -= i + 1

                # Insert starting token
                block[m] = annotation.fgcolor + annotation.bgcolor + block[m]

                # Insert ending token
                block[n] += colored.attr("reset")

            byte_lines.append(" ".join(block))

        # Now, create annotation lines for the blocks
        annotation_lines = ["" for _ in range(len(byte_lines))]

        for annotation in self.annotations:
            # Find the line corresponding to this start byte
            i = annotation.start_byte // BLOCK_SIZE
            while annotation_lines[i] != "":
                i += 1

                # Expand line count if necessary
                if i >= len(annotation_lines):
                    annotation_lines.append("")

            annotation_lines[i] = annotation.fgcolor + annotation.bgcolor + annotation.msg + colored.attr("reset")

        # Create empty byte lines if we need
        while len(annotation_lines) > len(byte_lines):
            byte_lines.append("")

        # Finally, assemble all lines
        output = ""
        for i, (byte_line, annotation_line) in enumerate(zip(byte_lines, annotation_lines)):
            # Start constructing line
            line = ""

            # Add index
            line += "{0:08x}".format(i * BLOCK_SIZE)
            line += "|\t"
            line += byte_line
            line += "\t\t"
            line += annotation_line

            output += line + "\n"
        return output

