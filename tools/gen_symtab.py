#!/usr/bin/env python3
'''
Embedded symbol table generator.
'''

import sys

symtab_size = 0
symtab = []

for line in sys.stdin:
    line = line.strip()
    parts = line.split(' ')
    del parts[2]

    if len(parts) != 3 or parts[2].startswith("__func__."):
        continue

    symtab.append("{ 0x%s, 0x%s, \"%s\" }" % tuple(parts))
    symtab_size += 1

print("#include <kern/symbol.h>")
print("const struct symbol symbol_table[] __symbol_table = {")

for elem in symtab:
    print("    " + elem + ",",)

print("};")
print("const size_t symbol_table_size = %d;" % symtab_size)
print("const struct symbol *symbol_table_ptr = symbol_table;")
