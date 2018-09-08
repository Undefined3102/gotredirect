#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "process_info.h"

#define PATH_SIZE 256
#define BUF_SIZE  256
int get_process_info(pid_t pid, process_info *p_info) {
    char path[PATH_SIZE];
    char buf[BUF_SIZE];
    FILE *fd;

    snprintf(path, PATH_SIZE-1, "/proc/%d/maps", pid);
    fd = fopen(path, "r");
    if(fd == NULL) {
        fprintf(stderr, "Failed to open %s\n", path);
        return -1;
    }

    // parse maps file
    p_info->exec_name = NULL;
    while(fgets(buf, BUF_SIZE-1, fd)) {
        if(strstr(buf, "r-xp") && !strstr(buf, ".so")) {
            *strchr(buf, '\n') = 0; // delete \n character

            p_info->base_addr = strtoul(buf, NULL, 16);
            p_info->exec_name = strdup(strchr(buf, '/'));
            if(p_info->exec_name == NULL)
                perror("strdup");
            break;
        }
    }

    fclose(fd);

    if(p_info->exec_name == NULL) {
        fprintf(stderr, "Failed to parse %s\n", path);
        return -1;
    }

    return 0;
}
