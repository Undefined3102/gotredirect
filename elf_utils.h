#pragma once
#include <stdint.h>
#include <elf.h>

#include "operation.h"

Elf32_Shdr* section_by_type(uint8_t *mem, Elf32_Word sh_type);
Elf32_Shdr* section_by_name(uint8_t *mem, const char *sh_name);

Elf32_Rel* rel_by_name(uint8_t *mem, const char *sym_name);
Elf32_Sym* symbol_by_name(uint8_t *mem, const char *sym_name);

int lib_check(uint8_t *lib_mem, const char *filename);
int grab_operation_info(uint8_t *exec_mem, uint8_t *lib_mem, uint32_t e_base_addr, operation *op);
