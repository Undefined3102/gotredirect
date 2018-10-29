#include <stdio.h>
#include <string.h>
#include <elf.h>

#include "elf_utils.h"
#include "operation.h"

Elf32_Shdr* section_by_type(uint8_t *mem, Elf32_Word sh_type) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)mem;
    Elf32_Shdr *shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);
    int i;

    for(i = 0; i < ehdr->e_shnum; i++) {
        if(shdr->sh_type == sh_type)
            return shdr;
        shdr++;
    }

    return NULL;
}


Elf32_Shdr* section_by_name(uint8_t *mem, const char *sh_name) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)mem;
    Elf32_Shdr *shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);
    char *strtab     = (char*)&mem[shdr[ehdr->e_shstrndx].sh_offset];
    int i;

    for(i = 0; i < ehdr->e_shnum; i++) {
        if(strcmp(strtab + shdr->sh_name, sh_name) == 0)
            return shdr;
        shdr++;
    }

    return NULL;
}


Elf32_Rel* rel_by_name(uint8_t *mem, const char *sym_name) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)mem;
    Elf32_Shdr *shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);

    Elf32_Shdr *sh_rel = section_by_name(mem, ".rel.plt");
    if(sh_rel == NULL || sh_rel->sh_type != SHT_REL)
        return NULL;

    Elf32_Rel *reltab  = (Elf32_Rel*)(mem + sh_rel->sh_offset);
    Elf32_Shdr *sh_sym = (Elf32_Shdr*)(shdr + sh_rel->sh_link);
    Elf32_Sym *symtab  = (Elf32_Sym*)(mem + sh_sym->sh_offset);
    char *strtab       = (char*)(mem + shdr[sh_sym->sh_link].sh_offset);
    int rel_count      = sh_rel->sh_size/sizeof(Elf32_Rel);
    int i, index;

    for(i = 0; i < rel_count; i++) {
        index = ELF32_R_SYM(reltab->r_info);
        if(strcmp(&strtab[symtab[index].st_name], sym_name) == 0)
            return reltab;
        reltab++;
    }

    return NULL;
}

Elf32_Sym* symbol_by_name(uint8_t *mem, const char *sym_name) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)mem;
    Elf32_Shdr *shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);

    Elf32_Shdr *sh_sym = section_by_type(mem, SHT_DYNSYM);
    if(sh_sym == NULL)
        return NULL;

    Elf32_Sym *symtab = (Elf32_Sym*)(mem + sh_sym->sh_offset);
    char *strtab      = (char*)(mem + shdr[sh_sym->sh_link].sh_offset);
    int sym_count     = sh_sym->sh_size/sizeof(Elf32_Sym);
    int i;

    for(i = 0; i < sym_count; i++) {
        if(strcmp(&strtab[symtab->st_name], sym_name) == 0)
            return symtab;
        symtab++;
    }

    return NULL;
}

int lib_check(uint8_t *lib_mem, const char *filename) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)lib_mem;

    if(memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "%s not ELF file\n", filename);
        return -1;
    }
    if(ehdr->e_type != ET_DYN) {
        fprintf(stderr, "%s e_type not ET_DYN\n", filename);
        return -1;
    }
    if(ehdr->e_machine != EM_386) {
        fprintf(stderr, "%s e_machine not EM_386\n", filename);
        return -1;
    }

    return 0;
}

int grab_operation_info(uint8_t *exec_mem, uint8_t *lib_mem, uint32_t e_base_addr, operation *op) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)exec_mem;

    Elf32_Rel *rel = rel_by_name(exec_mem, op->orig_func);
    if(rel == NULL)
        return -1;

    Elf32_Sym *sym = symbol_by_name(lib_mem, op->repl_func);
    if(sym == NULL)
        return -1;

    op->orig_offset = (ehdr->e_type == ET_DYN) ? (e_base_addr + rel->r_offset) : rel->r_offset;
    op->repl_offset = sym->st_value;

    return 0;
}
