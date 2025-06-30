#include "my_strace.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>


/// print information on syscall based on syscall number, syscall args and the return value
void print_syscall(unsigned long long syscall_number, unsigned long long syscall_args[], unsigned long long return_value) {
    unsigned char arg_count;
    unsigned char i;
    if (syscall_number < SYSCALL_LIST_LENGTH) {
        printf("%s(", syscalls[syscall_number]);
        arg_count = syscalls_arg_count[syscall_number];
    } else {
        printf("unknown-syscall-%llu(", syscall_number);
        arg_count = MAX_ARG_COUNT;
    }
    if (arg_count > 0) {
        for (i = 0; i < arg_count - 1; i++) {
            printf("%llu, ", syscall_args[i]);
        }
        printf("%llu", syscall_args[i]);
    }
    printf(") = %llu\n", return_value);
}

/// trace the process described by pid and print syscalls made by it
void handle_tracing(pid_t pid) {
    int status;
    unsigned long long syscall_number;
    unsigned long long return_value;
    struct user_regs_struct regs;
    unsigned long long syscall_args[6];

    // wait for child process start
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        return;
    }

    // main body
    while (1) {
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            break;
        }

        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        syscall_number = regs.orig_rax;
        syscall_args[0] = regs.rdi;
        syscall_args[1] = regs.rsi;
        syscall_args[2] = regs.rdx;
        syscall_args[3] = regs.r10;
        syscall_args[4] = regs.r8;
        syscall_args[5] = regs.r9;

        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            break;
        }

        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        return_value = regs.rax;
        
        print_syscall(syscall_number, syscall_args, return_value);
    }
}

/// strace for an application that can be executed with argv and argp
void strace(char* argv[], char* argp[]) {
    pid_t pid = fork();

    if (!pid) {
        // child process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (execve(argv[0], argv, argp) == -1) {
            printf("There was an error with execve\n");
            exit(ERROR_EXIT_STATUS);
        }
    }

    // parent process
    handle_tracing(pid);
}

