#pragma once
#include <stdint.h>
#include <sys/wait.h>

typedef struct {
    uintptr_t base_addr;
    char      *exec_name;
} process_info;

int get_process_info(pid_t pid, process_info *p_info);
