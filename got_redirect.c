#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include "operation.h"
#include "process_info.h"
#include "elf_utils.h"

#define Word_align(x) ((x+3) & -4)

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


int pid_read(pid_t pid, void *dst, const void *src, int len) {
    int sz = Word_align(len)/sizeof(long);
    long word;

    while(sz > 0) {
        word = ptrace(PTRACE_PEEKTEXT, pid, src, NULL);
        if(word < 0 && errno)
            goto error;

        *(long*)dst = word;
        src += sizeof(long);
        dst += sizeof(long);
        sz--;
    }

    return len;
error:
    perror("PTRACE_PEEKTEXT");
    return -1;
}

int pid_write(pid_t pid, void *dst, const void *src, int len) {
    int sz = len/sizeof(long);

    while(sz > 0) {
        if(ptrace(PTRACE_POKETEXT, pid, dst, (void*)(*(long*)src)) < 0)
            goto error;
        src += sizeof(long);
        dst += sizeof(long);
        sz--;
    }

    return len;
error:
    perror("PTRACE_POKETEXT");
    return -1;
}

int main(int argc, char *argv[]) {
/*
    jmp B
A:
    movl $5, %eax
    popl %ebx
    xorl %ecx, %ecx
    int $0x80

    subl $24, %esp

    xorl %edx, %edx
    movl %edx, (%esp)
    movl $8192, 4(%esp)
    movl $7, 8(%esp)
    movl $2, 12(%esp)
    movl %eax, 16(%esp)
    movl %edx, 20(%esp)
    movl $90, %eax
    movl %esp, %ebx
    int $0x80

    int3
B:
    call A
*/
    uint8_t shellcode[] = {0xeb,0x3c,0xb8,0x5,0x0,0x0,0x0,0x5b,0x31,0xc9,0xcd,0x80,0x83,0xec,0x18,0x31,0xd2,0x89,0x14,0x24,0xc7,0x44,0x24,0x4,0x0,0x20,0x0,0x0,0xc7,0x44,0x24,0x8,0x7,0x0,0x0,0x0,0xc7,0x44,0x24,0xc,0x2,0x0,0x0,0x0,0x89,0x44,0x24,0x10,0x89,0x54,0x24,0x14,0xb8,0x5a,0x0,0x0,0x0,0x89,0xe3,0xcd,0x80,0xcc,0xe8,0xbf,0xff,0xff,0xff};

    pid_t pid;
    char *lib_path;
    process_info p_info;
    uint8_t *exec_mem, *lib_mem;
    uint32_t exec_mem_size, lib_mem_size;

    operation *operations, *op;
    int i;

    int status;

    uint32_t code_len, got_value;
    uint8_t *orig_code, *patched_shellcode;

    struct user_regs_struct pt_reg, pt_reg_bak;

    if(argc < 4) {
        fprintf(stderr, "Usage: %s <pid> <lib.so> <original_function,replacer_function,[patch_offset]>...\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // parse command line's arguments
    pid               = atoi(argv[1]);
    lib_path          = realpath(argv[2], NULL);
    operations        = NULL;
    p_info.exec_name  = NULL;
    exec_mem          = NULL;
    lib_mem           = NULL;
    orig_code         = NULL;
    patched_shellcode = NULL;

    if(lib_path == NULL) {
        perror("realpath");
        goto cleanup;
    }

    for(i = 3; i < argc; i++) {
        op = parse_operation(argv[i]);
        if(op == NULL)
            goto cleanup;
        operations = push_operation(operations, op);
    }
    // end of parsing

    if(get_process_info(pid, &p_info) < 0)
        goto cleanup;

    exec_mem = mmap_read_file(p_info.exec_name, &exec_mem_size);
    if(exec_mem == NULL)
        goto cleanup;

    lib_mem = mmap_read_file(lib_path, &lib_mem_size);
    if(lib_mem == NULL)
        goto cleanup;

    if(lib_check(lib_mem, lib_path) < 0)
        goto cleanup;

    //grab operation info
    for(op = operations; op != NULL; op = op->next) {
        if(grab_operation_info(exec_mem, lib_mem, p_info.base_addr, op) < 0) {
            fprintf(stderr, "Failed to find %s and %s functions in %s and %s",
                            op->orig_func,
                            op->repl_func,
                            p_info.exec_name,
                            lib_path);
            goto cleanup;
        }
    }

    // free exec_mem and lib_mem
    munmap(exec_mem, exec_mem_size);
    munmap(lib_mem, lib_mem_size);
    exec_mem = NULL;
    lib_mem = NULL;

    // create buffers for shellcode
    code_len = Word_align(sizeof(shellcode) + strlen(lib_path) + 1);

    orig_code = malloc(code_len);
    if(orig_code == NULL) {
        perror("malloc");
        goto cleanup;
    }

    patched_shellcode = malloc(code_len);
    if(patched_shellcode == NULL) {
        perror("malloc");
        goto cleanup;
    }

    // copy shellcode to patched_shellcode and append lib_path after that
    memcpy(patched_shellcode, shellcode, sizeof(shellcode));
    memcpy(&patched_shellcode[sizeof(shellcode)], lib_path, code_len-sizeof(shellcode));

    //attach to process
    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("PTRACE_ATTACH");
        goto cleanup;
    }
    wait(NULL);

    // get registers
    if(ptrace(PTRACE_GETREGS, pid, NULL, &pt_reg) < 0) {
        perror("PTRACE_GETREGS");
        goto cleanup;
    }
    pt_reg_bak = pt_reg;

    // backup original code and write shellcode
    if(pid_read(pid, (void*)orig_code, (void*)pt_reg.eip, code_len) < 0)
        goto cleanup;
    if(pid_write(pid, (void*)pt_reg.eip, (void*)patched_shellcode, code_len) < 0)
        goto cleanup;
    if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        perror("PTRACE_CONT");
        goto cleanup;
    }
    wait(&status);

    // test if stoped by int3
    if(WSTOPSIG(status) != SIGTRAP) {
        fputs("Something went wrong", stderr);
        goto cleanup;
    }

    // get registers to get base address of payload library
    if(ptrace(PTRACE_GETREGS, pid, NULL, &pt_reg) < 0) {
        perror("PTRACE_GETREGS");
        goto cleanup;
    }

    // got redirect
    for(op = operations; op != NULL; op = op->next) {
        // after mmap syscall eax contain base address of payload lib
        op->repl_offset += pt_reg.eax;
        
        // if patch_offset is set, write address of original function by patch_offset
        if(op->patch_offset > 0) {
            if(pid_read(pid, (void*)&got_value, (void*)op->orig_offset, sizeof(uint32_t)) < 0)
                goto cleanup;
            if(pid_write(pid, (void*)(op->repl_offset + op->patch_offset), (void*)&got_value, sizeof(uint32_t)) < 0)
                goto cleanup;
        }

        // patch got entry
        if(pid_write(pid, (void*)op->orig_offset, (void*)&op->repl_offset, sizeof(uint32_t)) < 0)
            goto cleanup;
    }

    // restore original code and registers
    if(pid_write(pid, (void*)pt_reg_bak.eip, (void*)orig_code, code_len) < 0)
        goto cleanup;
    if(ptrace(PTRACE_SETREGS, pid, NULL, &pt_reg_bak) < 0) {
        perror("PTRACE_SETREGS");
        goto cleanup;
    }

    // detach from process
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
cleanup:
    if(lib_path) free(lib_path);
    if(p_info.exec_name) free(p_info.exec_name);
    if(operations) free_operations(operations);
    if(exec_mem) munmap(exec_mem, exec_mem_size);
    if(lib_mem) munmap(lib_mem, lib_mem_size);
    if(orig_code) free(orig_code);
    if(patched_shellcode) free(patched_shellcode);
}
