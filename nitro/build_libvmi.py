#!/usr/bin/env python3

import sys
import os
from cffi import FFI

CDEF_FILE = 'libvmi_cdef.h'

if __name__ == "__main__":
    ffibuilder = FFI()
    # set source
    ffibuilder.set_source("_libvmi",
    """
    #include <libvmi/libvmi.h>
    """,
    libraries=['vmi'])
    # set cdef
    cdef_content = None
    # we read our C definitions from an external file
    # easier to maintain + C syntax highlighting
    with open(os.path.join(sys.path[0], CDEF_FILE)) as cdef_file:
        cdef_content = cdef_file.read()
    ffibuilder.cdef(cdef_content)

    ffibuilder.compile(verbose=True)

