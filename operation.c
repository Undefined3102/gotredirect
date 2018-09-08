#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "operation.h"

void print_parse_error(parse_error error, char *str) {
    switch(error) {
        case NO_ERROR:
            fputs("parse was successful", stderr);
            break;
        case MALLOC_ERROR:
            perror("parse error. malloc");
            break;
        case FORMAT_ERROR:
            fprintf(stderr, "%s have a wrong format. format: original_function,replacer_function,[patch_offset]\n", str);
            break;
    }
}

operation* parse_operation(char *str, parse_error *error) {
    operation *r;
    char *p;
    int i;

    r = malloc(sizeof(operation));
    if(r == NULL) {
        *error = MALLOC_ERROR;
        goto error;
    }
    *r = (operation) {
        .orig_func = NULL,
        .repl_func = NULL,
        .orig_offset = 0,
        .repl_offset = 0,
        .patch_offset = 0,
        .next = NULL
    };
    i = 0;
    *error = NO_ERROR;

    p = strtok(str, ",");
    while(p != NULL) {
        if(i == 0) {
            r->orig_func = strdup(p);
        } else if(i == 1) {
            r->repl_func = strdup(p);
        } else if(i == 2) {
            r->patch_offset = atoi(p);
        }

        p = strtok(NULL, ",");
        if(p != NULL) *(p-1) = ',';
        i++;
    }

    if(i != 2 && i != 3) {
        *error = FORMAT_ERROR;
        goto error;
    }

    if(r->orig_func == NULL || r->repl_func == NULL) {
        *error = MALLOC_ERROR;
        goto error;
    }

    return r;
error:
    if(r) {
        if(r->orig_func) free(r->orig_func);
        if(r->repl_func) free(r->repl_func);
        free(r);
    }
    return NULL;
}


operation* push_operation(operation *root, operation *op) {
    op->next = root;
    return op;
}


void free_operations(operation *root) {
    operation *i;
    while(root) {
        i = root;
        root = root->next;
        free(i->orig_func);
        free(i->repl_func);
        free(i);
    }
}
