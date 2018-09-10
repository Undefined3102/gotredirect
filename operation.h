#pragma once
#include <stdint.h>

typedef struct operation {
    char             *orig_func;
    char             *repl_func;
    uint32_t         orig_offset;
    uint32_t         repl_offset;
    uint32_t         patch_offset;
    struct operation *next;
} operation;

operation* parse_operation(char *str);
operation* push_operation(operation *root, operation *op);
void free_operations(operation *root);
