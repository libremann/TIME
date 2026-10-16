/*  MIT License

    Copyright (c) 2025 Mahdi Hosseini Asaad

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/mman.h>
#include<unistd.h>
#include<sys/ptrace.h>
#include<signal.h>
#include<sys/wait.h>
#include<sys/user.h>
#include<signal.h>
#include<dlfcn.h>

unsigned char *shared_code;
struct user_regs_struct regs;

static int monitor(char *, struct user_regs_struct *, pid_t);

void sigint_handler(int sig) {
    __asm__ volatile("int3");
}

int main() {
	ptrace(PTRACE_ATTACH, 9049);
	shared_code = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if(shared_code==MAP_FAILED) {
		perror("mmap failed");
		return 1;
    }

	struct user_regs_struct regs;
	unsigned ind=0;
    char input[100];
    char *token;

	pid_t pid = fork();

	if(pid==0) {
		signal(SIGINT, sigint_handler);
		
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		raise(SIGSTOP);

		void (*func)() = (void(*)())shared_code;

		func(); // If the user does not include an exit instruction themselves, 'TIME' will exit with code 1 by default.
		exit(1);

	} else {
		int status;
        signal(SIGINT, SIG_IGN);
		
		while(1) {
			waitpid(pid, &status, 0);

			if (WIFSTOPPED(status)) {
				int sig = WSTOPSIG(status);

L1:
				printf("%2d %p: ", sig, (shared_code+ind));

			    fgets(input, sizeof(input), stdin);
    			input[strcspn(input, "\n")] = '\0';

				token=strtok(input, " ");
				while (token!=NULL) {
                    if(monitor(token, &regs, pid)) goto L1;

					unsigned int value;
					sscanf(token, "%x", &value);
					
					shared_code[ind++]=value;
					token = strtok(NULL, " ");
				}
				shared_code[ind++]=0xcc;
				ptrace(PTRACE_CONT, pid, NULL, NULL);
			} else if (WIFEXITED(status)) {
				printf("Exit Normally :)\n");
    			munmap(shared_code, 4096);
				return 0;
			}
		}
	}
}

void monitor_reg(char *, struct user_regs_struct *, pid_t);

static int monitor(char *token, struct user_regs_struct *regs, pid_t pid) {
    if(strcmp(token, ".fnc")==0) {
        token=strtok(NULL, " ");
        if(token!=NULL) printf("address of %s: %p", token, (void*)dlsym(RTLD_DEFAULT, token));
        else printf("SYNTEX ERROR: '.fnc <fnc name>'");
        puts("\n");
        return 1;
    } else if(strcmp(token, ".adr")==0) {
        token=strtok(NULL, " ");
        if(strcmp(token, "stdout")==0) printf("address of stdout: %p", (void*)stdout);
        else if(strcmp(token, "stdin")==0) printf("address of stdin: %p", (void*)stdin);
        else if(strcmp(token, "stderr")==0) printf("address of stderr: %p", (void*)stderr);
        else printf(".adr <stdin/stdout/stderr>");
        puts("\n");
        return 1;
    } else if(strcmp(token, ".reg")==0) {
        token=strtok(NULL, " ");
        monitor_reg(token, regs, pid);
        return 1;
    }
    return 0;
}

void monitor_reg(char *token, struct user_regs_struct *regs, pid_t pid) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs)==0) {
    #if defined(__linux__) && defined(__x86_64__)
        if      (strcmp(token, "rax")==0)      printf("RAX: %llx", (unsigned long long)regs->rax);
        else if (strcmp(token, "rbx")==0)      printf("RBX: %llx", (unsigned long long)regs->rbx);
        else if (strcmp(token, "rcx")==0)      printf("RCX: %llx", (unsigned long long)regs->rcx);
        else if (strcmp(token, "rdx")==0)      printf("RDX: %llx", (unsigned long long)regs->rdx);
        else if (strcmp(token, "rsi")==0)      printf("RSI: %llx", (unsigned long long)regs->rsi);
        else if (strcmp(token, "rdi")==0)      printf("RDI: %llx", (unsigned long long)regs->rdi);
        else if (strcmp(token, "rbp")==0)      printf("RBP: %llx", (unsigned long long)regs->rbp);
        else if (strcmp(token, "rsp")==0)      printf("RSP: %llx", (unsigned long long)regs->rsp);
        else if (strcmp(token, "r8")==0)       printf("R8: %llx",  (unsigned long long)regs->r8);
        else if (strcmp(token, "r9")==0)       printf("R9: %llx",  (unsigned long long)regs->r9);
        else if (strcmp(token, "r10")==0)      printf("R10: %llx", (unsigned long long)regs->r10);
        else if (strcmp(token, "r11")==0)      printf("R11: %llx", (unsigned long long)regs->r11);
        else if (strcmp(token, "r12")==0)      printf("R12: %llx", (unsigned long long)regs->r12);
        else if (strcmp(token, "r13")==0)      printf("R13: %llx", (unsigned long long)regs->r13);
        else if (strcmp(token, "r14")==0)      printf("R14: %llx", (unsigned long long)regs->r14);
        else if (strcmp(token, "r15")==0)      printf("R15: %llx", (unsigned long long)regs->r15);
        else if (strcmp(token, "rip")==0)      printf("RIP: %llx", (unsigned long long)regs->rip);
        else if (strcmp(token, "eflags")==0)   printf("EFLAGS: %llx", (unsigned long long)regs->eflags);
        else if (strcmp(token, "cs")==0)       printf("CS: %llx",  (unsigned long long)regs->cs);
        else if (strcmp(token, "ss")==0)       printf("SS: %llx",  (unsigned long long)regs->ss);
        else if (strcmp(token, "ds")==0)       printf("DS: %llx",  (unsigned long long)regs->ds);
        else if (strcmp(token, "es")==0)       printf("ES: %llx",  (unsigned long long)regs->es);
        else if (strcmp(token, "fs")==0)       printf("FS: %llx",  (unsigned long long)regs->fs);
        else if (strcmp(token, "gs")==0)       printf("GS: %llx",  (unsigned long long)regs->gs);
        else if (strcmp(token, "fs_base")==0)  printf("FS_BASE: %llx",  (unsigned long long)regs->fs_base);
        else if (strcmp(token, "gs_base")==0)  printf("GS_BASE: %llx",  (unsigned long long)regs->gs_base);
        else if (strcmp(token, "orig_rax")==0) printf("ORIG_RAX: %llx", (unsigned long long)regs->orig_rax);
        else printf(".reg <register name>");
        puts("\n");

    #else
    #warning "Register inspection is not implemented for this platform"
        puts("Register inspection doesn't supprot on your platform\n");
    #endif

        return;
    }
}