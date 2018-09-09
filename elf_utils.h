#pragma once
#include <stdint.h>
#include <elf.h>

#include "operation.h"

void* mmap_read_file(const char *filename, uint32_t *size);
Elf32_Shdr* find_section(uint8_t *mem, const char *sh_name);
Elf32_Rel* find_symbol_rel(uint8_t *mem, const char *sh_name, const char *sym_name);
Elf32_Sym* find_symbol(uint8_t *mem, const char *sh_name, const char *sym_name);

int elf_check(uint8_t *lib_mem, const char *filename);
int grab_operation_info(uint8_t *exec_mem, uint8_t *lib_mem, uint32_t e_base_addr, operation *op);
