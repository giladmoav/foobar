#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

#define ERROR_EXIT_STATUS -1


/// trace the process described by pid and print syscalls made by it
void handle_tracing(pid_t pid) {
    int status;
    unsigned long long syscall_number;
    unsigned long long return_value;
    struct user_regs_struct regs;

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

        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            break;
        }

        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        return_value = regs.rax;
        
        printf("%llu -> %llu\n", syscall_number, return_value);
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

void main(int argc, char* argv[], char* argp[]) {
    if (argc < 2) {
        printf("Usage: %s BINARY ARGS\n", argv[0]);
        exit(ERROR_EXIT_STATUS);
    }

    strace(argv + 1, argp);
}

