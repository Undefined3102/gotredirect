#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

#include "elf_utils.h"
#include "operation.h"

void* mmap_read_file(const char *filename, uint32_t *size) {
    int fd;
    struct stat f_info;
    void *mem;

    mem = MAP_FAILED;

    fd = open(filename, O_RDONLY);
    if(fd < 0) {
        perror("open");
        goto cleanup;
    }

    if(fstat(fd, &f_info) < 0) {
        perror("fstat");
        goto cleanup;
    }

    mem = mmap(NULL, f_info.st_size, PROT_READ, MAP_PRIVATE, fd, 0); 
    if(mem == MAP_FAILED) {
        perror("mmap");
        goto cleanup;
    }

    *size = f_info.st_size;
cleanup:
    if(fd >= 0) close(fd);
    return (mem == MAP_FAILED ? NULL : mem);
}

Elf32_Shdr* find_section(uint8_t *mem, const char *sh_name) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)mem;
    Elf32_Shdr *shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);
    char *strtab = (char*)&mem[shdr[ehdr->e_shstrndx].sh_offset];
    int i;

    for(i = 0; i < ehdr->e_shnum; i++) {
        if(strcmp(&strtab[shdr[i].sh_name], sh_name) == 0)
            return &shdr[i];
    }

    return NULL;
}

Elf32_Rel* find_symbol_rel(uint8_t *mem, const char *sh_name, const char *sym_name) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)mem;
    Elf32_Shdr *shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);

    Elf32_Shdr *sh_rel = find_section(mem, sh_name);
    if(sh_rel == NULL || sh_rel->sh_type != SHT_REL)
        return NULL;

    Elf32_Rel *reltab  = (Elf32_Rel*)(mem + sh_rel->sh_offset);
    Elf32_Shdr *sh_sym = (Elf32_Shdr*)(shdr + sh_rel->sh_link);
    Elf32_Sym *symtab  = (Elf32_Sym*)(mem + sh_sym->sh_offset);
    char *strtab       = (char*)(mem + shdr[sh_sym->sh_link].sh_offset);
    int rel_count      = sh_rel->sh_size/sizeof(Elf32_Rel);
    int i, index;

    for(i = 0; i < rel_count; i++) {
        index = ELF32_R_SYM(reltab[i].r_info);
        if(strcmp(&strtab[symtab[index].st_name], sym_name) == 0)
            return &reltab[i];
    }

    return NULL;
}

Elf32_Sym* find_symbol(uint8_t *mem, const char *sh_name, const char *sym_name) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr*)mem;
    Elf32_Shdr *shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);

    Elf32_Shdr *sh_sym = find_section(mem, sh_name);
    if(sh_sym == NULL || sh_sym->sh_type != SHT_DYNSYM)
        return NULL;

    Elf32_Sym *symtab = (Elf32_Sym*)(mem + sh_sym->sh_offset);
    char *strtab      = (char*)(mem + shdr[sh_sym->sh_link].sh_offset);
    int sym_count     = sh_sym->sh_size/sizeof(Elf32_Sym);
    int i;

    for(i = 0; i < sym_count; i++) {
        if(strcmp(&strtab[symtab[i].st_name], sym_name) == 0)
            return &symtab[i];
    }

    return NULL;
}


int elf_check(uint8_t *lib_mem, const char *filename) {
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

    Elf32_Rel *rel = find_symbol_rel(exec_mem, ".rel.plt", op->orig_func);
    rel = rel == NULL ? find_symbol_rel(exec_mem, ".rel.dyn", op->orig_func) : rel;
    if(rel == NULL)
        return -1;

    Elf32_Sym *sym = find_symbol(lib_mem, ".dynsym", op->repl_func);
    if(sym == NULL)
        return -1;

    op->orig_offset = (ehdr->e_type == ET_DYN) ? (e_base_addr + rel->r_offset) : rel->r_offset;
    op->repl_offset = sym->st_value;

    return 0;
}
