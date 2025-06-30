#include "my_strace.h"
#include <stdio.h>

void main(int argc, char* argv[], char* argp[]) {
    if (argc < 2) {
        printf("Usage: %s BINARY ARGS\n", argv[0]);
        exit(ERROR_EXIT_STATUS);
    }

    strace(argv + 1, argp);
}

