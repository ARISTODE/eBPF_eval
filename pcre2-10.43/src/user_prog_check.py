from bcc import BPF
from ctypes import cast, POINTER, c_char

include_path = "-I/usr/include/"
def_path = "-I/usr/include/clang/10/include/"
b = BPF(src_file="user_prog_check.c", cflags=["-O2", include_path, def_path], debug=0)

while True:
  try:
    b.trace_print()
  except KeyboardInterrupt:
    break
