#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <dlfcn.h>

#define CODE_SIZE 4096
#define DATA_SIZE (1024 * 1024)

unsigned char *shared_code;
unsigned char *shared_data;
struct user_regs_struct regs;
char input[100];

static size_t data_ind=0;

static int monitor(char *, struct user_regs_struct *, pid_t);
static void monitor_reg(char *, struct user_regs_struct *, pid_t);
static void create_buffer(void);

void sigint_handler(int sig)
{
   (void)sig;
    raise(SIGTRAP);
}

static int parse_number(const char *s, int base, unsigned long *value)
{
    char *end;
    unsigned long n;

    if(s==NULL || *s=='\0' || *s=='-') {
        return 0;
    }

    errno=0;
    n=strtoul(s, &end, base);

    if(errno==ERANGE || end==s || *end!='\0') {
        return 0;
    }

    *value=n;
    return 1;
}

static void create_buffer(void)
{
    char *token;
    char *token_p;
    char *saveptr=NULL;
    char type;
    unsigned long size_value;
    size_t buf_size;
    size_t ind=0;
    unsigned char *buffer;

    token=strtok(NULL, " \t");

    if(token==NULL) {
        printf(".buf <str|hex|dec> <buffer size>\n");
        return;
    }

    if(strcmp(token, "str")==0) {
        type='c';
    } else if(strcmp(token, "hex")==0) {
        type='x';
    } else if(strcmp(token, "dec")==0) {
        type='d';
    } else {
        fprintf(stderr, "Invalid buffer type\n");
        return;
    }

    token=strtok(NULL, " \t");

    if(token==NULL ||
        !parse_number(token, 10, &size_value) ||
        size_value==0 ||
        size_value > SIZE_MAX) {
        fprintf(stderr, "Buffer size must be a positive integer\n");
        return;
    }

    buf_size=(size_t)size_value;

    if(data_ind > DATA_SIZE || buf_size > DATA_SIZE - data_ind) {
        fprintf(stderr, "Shared data area is full\n");
        return;
    }

    buffer=shared_data+data_ind;
    data_ind += buf_size;

    while(ind < buf_size) {
        size_t remaining=buf_size - ind;

        printf("%p: ",(void *)(buffer+ind));
        fflush(stdout);

        if(fgets(input, sizeof(input), stdin)==NULL) {
            return;
        }

        input[strcspn(input, "\n")]='\0';

        if(type=='c') {
            size_t len=strlen(input);

            if(len+1 > remaining) return;

            memcpy(buffer+ind, input, len);
            buffer[ind+len]='\0';
            ind += len+1;
        } else {
            token_p=strtok_r(input, " \t", &saveptr);

            while(token_p!=NULL) {
                unsigned long value;
                int base=(type=='x') ? 16 : 10;

                if(!parse_number(token_p, base, &value) || value > 255) {
                    fprintf(stderr, "Invalid byte value: %s\n", token_p);
                    token_p=strtok_r(NULL, " \t", &saveptr);
                    continue;
                }

                if(ind>=buf_size) {
                    return;
                }

                buffer[ind++]=(unsigned char)value;
                token_p=strtok_r(NULL, " \t", &saveptr);
            }
        }

        if(ind>=buf_size) return;
    }
}

int main(void) {
    pid_t pid;
    int status;
    unsigned int ind=0;
    char *token;

    shared_code=mmap(
        NULL,
        CODE_SIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0
    );

    if(shared_code==MAP_FAILED) {
        perror("mmap shared_code");
        return 1;
    }

    shared_data=mmap(
        NULL,
        DATA_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0
    );

    if(shared_data==MAP_FAILED) {
        perror("mmap shared_data");
        munmap(shared_code, CODE_SIZE);
        return 1;
    }

    pid=fork();

    if(pid==-1) {
        perror("fork");
        munmap(shared_code, CODE_SIZE);
        munmap(shared_data, DATA_SIZE);
        return 1;
    }

    if(pid==0) {
        void(*func)(void)=(void(*)(void))shared_code;

        signal(SIGINT, sigint_handler);

        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL)==-1) {
            perror("ptrace PTRACE_TRACEME");
            _exit(1);
        }

        if(raise(SIGSTOP)!=0) {
            perror("raise SIGSTOP");
            _exit(1);
        }

        func();
        _exit(1);
    }

    signal(SIGINT, SIG_IGN);

    for(;;) {

        pid_t waited=waitpid(pid, &status, 0);

        if(waited==-1) {
            if(errno==EINTR) {
                continue;
            }

            perror("waitpid");
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            munmap(shared_code, CODE_SIZE);
            munmap(shared_data, DATA_SIZE);
            return 1;
        }

        if(WIFSTOPPED(status)) {
            int sig=WSTOPSIG(status);

            if(sig==SIGTRAP) {
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                regs.rip -= 1;
                ptrace(PTRACE_SETREGS, pid, NULL, &regs);
            }

            for(;;) {
                printf("%2d %p: ", sig, (void *)(shared_code+ind));
                fflush(stdout);

                if(fgets(input, sizeof(input), stdin)==NULL) {
                    kill(pid, SIGKILL);
                    waitpid(pid, NULL, 0);
                    munmap(shared_code, CODE_SIZE);
                    munmap(shared_data, DATA_SIZE);
                    return 0;
                }

                input[strcspn(input, "\n")]='\0';
                token=strtok(input, " \t");

                if(token==NULL) {
                    continue;
                }

                if(monitor(token, &regs, pid)) {
                    continue;
                }

                if(strcmp(token, ".buf")==0) {
                    create_buffer();
                    continue;
                }

                while(token!=NULL) {
                    unsigned long value;

                    if(monitor(token, &regs, pid)) {
                        break;
                    }

                    if(strcmp(token, ".buf")==0) {
                        create_buffer();
                        break;
                    }

                    if(!parse_number(token, 16, &value) || value > 255) {
                        fprintf(stderr, "Invalid byte: %s\n", token);
                        break;
                    }

                    if(ind>=CODE_SIZE - 1) {
                        fprintf(stderr, "Code area is full\n");
                        break;
                    }

                    shared_code[ind++]=(unsigned char)value;
                    token=strtok(NULL, " \t");
                }

                if(token!=NULL) {
                    continue;
                }

                if(ind>=CODE_SIZE) {
                    fprintf(stderr, "No space for int3\n");
                    continue;
                }

                shared_code[ind]=0xcc;

                if(ptrace(PTRACE_CONT, pid, NULL, NULL)==-1) {
                    perror("ptrace PTRACE_CONT");
                    kill(pid, SIGKILL);
                    waitpid(pid, NULL, 0);
                    munmap(shared_code, CODE_SIZE);
                    munmap(shared_data, DATA_SIZE);
                    return 1;
                }

                break;
            }
        } else if(WIFEXITED(status)) {
            printf("Exit Normally :)\n");
            munmap(shared_code, CODE_SIZE);
            munmap(shared_data, DATA_SIZE);
            return 0;
        } else if(WIFSIGNALED(status)) {
            fprintf(stderr, "Child terminated by signal %d\n",
                    WTERMSIG(status));
            munmap(shared_code, CODE_SIZE);
            munmap(shared_data, DATA_SIZE);
            return 1;
        }
    }
}

static int monitor(char *token, struct user_regs_struct *registers, pid_t pid)
{
    if(strcmp(token, ".fnc")==0) {
        token=strtok(NULL, " \t");

        if(token==NULL) {
            fprintf(stderr, "Syntax: .fnc <function name>\n");
        } else {
            dlerror();
            void *address=dlsym(RTLD_DEFAULT, token);
            const char *error=dlerror();

            if(error!=NULL) {
                fprintf(stderr, "%s\n", error);
            } else {
                printf("address of %s: %p\n", token, address);
            }
        }

        return 1;
    }

    if(strcmp(token, ".adr")==0) {
        token=strtok(NULL, " \t");

        if(token==NULL) {
            fprintf(stderr, "Syntax: .adr <stdin|stdout|stderr>\n");
        } else if(strcmp(token, "stdout")==0) {
            printf("address of stdout: %p\n",(void *)stdout);
        } else if(strcmp(token, "stdin")==0) {
            printf("address of stdin: %p\n",(void *)stdin);
        } else if(strcmp(token, "stderr")==0) {
            printf("address of stderr: %p\n",(void *)stderr);
        } else {
            fprintf(stderr, "Syntax: .adr <stdin|stdout|stderr>\n");
        }

        return 1;
    }

    if(strcmp(token, ".reg")==0) {
        token=strtok(NULL, " \t");

        if(token==NULL) {
            fprintf(stderr, "Syntax: .reg <register name>\n");
        } else {
            monitor_reg(token, registers, pid);
        }

        return 1;
    }

    return 0;
}

static void monitor_reg(char *token, struct user_regs_struct *registers,
                        pid_t pid)
{
    if(token==NULL) {
        fprintf(stderr, "Syntax: .reg <register name>\n");
        return;
    }

#if defined(__linux__) && defined(__x86_64__)
    if(ptrace(PTRACE_GETREGS, pid, NULL, registers)==-1) {
        perror("ptrace PTRACE_GETREGS");
        return;
    }

    if     (strcmp(token, "rax")==0)       printf("RAX: %llx\n",(unsigned long long)registers->rax);
    else if(strcmp(token, "rbx")==0)       printf("RBX: %llx\n",(unsigned long long)registers->rbx);
    else if(strcmp(token, "rcx")==0)       printf("RCX: %llx\n",(unsigned long long)registers->rcx);
    else if(strcmp(token, "rdx")==0)       printf("RDX: %llx\n",(unsigned long long)registers->rdx);
    else if(strcmp(token, "rsi")==0)       printf("RSI: %llx\n",(unsigned long long)registers->rsi);
    else if(strcmp(token, "rdi")==0)       printf("RDI: %llx\n",(unsigned long long)registers->rdi);
    else if(strcmp(token, "rbp")==0)       printf("RBP: %llx\n",(unsigned long long)registers->rbp);
    else if(strcmp(token, "rsp")==0)       printf("RSP: %llx\n",(unsigned long long)registers->rsp);
    else if(strcmp(token, "r8")==0)        printf("R8: %llx\n",(unsigned long long)registers->r8);
    else if(strcmp(token, "r9")==0)        printf("R9: %llx\n",(unsigned long long)registers->r9);
    else if(strcmp(token, "r10")==0)       printf("R10: %llx\n",(unsigned long long)registers->r10);
    else if(strcmp(token, "r11")==0)       printf("R11: %llx\n",(unsigned long long)registers->r11);
    else if(strcmp(token, "r12")==0)       printf("R12: %llx\n",(unsigned long long)registers->r12);
    else if(strcmp(token, "r13")==0)       printf("R13: %llx\n",(unsigned long long)registers->r13);
    else if(strcmp(token, "r14")==0)       printf("R14: %llx\n",(unsigned long long)registers->r14);
    else if(strcmp(token, "r15")==0)       printf("R15: %llx\n",(unsigned long long)registers->r15);
    else if(strcmp(token, "rip")==0)       printf("RIP: %llx\n",(unsigned long long)registers->rip);
    else if(strcmp(token, "eflags")==0)    printf("EFLAGS: %llx\n",(unsigned long long)registers->eflags);
    else if(strcmp(token, "cs")==0)        printf("CS: %llx\n",(unsigned long long)registers->cs);
    else if(strcmp(token, "ss")==0)        printf("SS: %llx\n",(unsigned long long)registers->ss);
    else if(strcmp(token, "ds")==0)        printf("DS: %llx\n",(unsigned long long)registers->ds);
    else if(strcmp(token, "es")==0)        printf("ES: %llx\n",(unsigned long long)registers->es);
    else if(strcmp(token, "fs")==0)        printf("FS: %llx\n",(unsigned long long)registers->fs);
    else if(strcmp(token, "gs")==0)        printf("GS: %llx\n",(unsigned long long)registers->gs);
    else if(strcmp(token, "fs_base")==0)   printf("FS_BASE: %llx\n",(unsigned long long)registers->fs_base);
    else if(strcmp(token, "gs_base")==0)   printf("GS_BASE: %llx\n",(unsigned long long)registers->gs_base);
    else if(strcmp(token, "orig_rax")==0)  printf("ORIG_RAX: %llx\n",(unsigned long long)registers->orig_rax);
    else fprintf(stderr, "Unknown register: %s\n", token);
#else
    fprintf(stderr, "Register inspection is not supported on this platform\n");
#endif
}