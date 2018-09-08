#pragma once
#include <stdint.h>

typedef enum {
    NO_ERROR,
    MALLOC_ERROR,
    FORMAT_ERROR
} parse_error;

typedef struct operation {
    char             *orig_func;
    char             *repl_func;
    uint32_t         orig_offset;
    uint32_t         repl_offset;
    uint32_t         patch_offset;
    struct operation *next;
} operation;

void print_parse_error(parse_error error, char *str);
operation* parse_operation(char *str, parse_error *error);

operation* push_operation(operation *root, operation *op);
void free_operations(operation *root);
