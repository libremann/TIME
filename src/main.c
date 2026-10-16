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

void sigint_handler(int sig) {
    __asm__ volatile("int3");
}

int main() {
	ptrace(PTRACE_ATTACH, 9049);
	shared_code = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if(shared_code == MAP_FAILED) {
		perror("mmap failed");
		return 1;
    }

	printf("address of stdout : %p\n", (void*)stdout);

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

				if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == 0) {
					printf("\033[90mRAX: %llx\n", regs.rax);
					printf("RBX: %llx\n", regs.rbx);
					printf("RIP: %llx\n", regs.rip);
				}
				printf("(signal=%d)\n\n", sig);
				printf("\033[0m");
L1:
				printf("%p: ", (shared_code+ind));

			    fgets(input, sizeof(input), stdin);
    			input[strcspn(input, "\n")] = '\0';

				token=strtok(input, " ");
				while (token!=NULL) {
					if(strcmp(token, ".fnc")==0) {
						token=strtok(NULL, " ");
						if(token!=NULL) printf("address of %s: %p", token, (void*)dlsym(RTLD_DEFAULT, token));
						else printf("SYNTEX ERROR: '.fnc <fnc>'");
						puts("\n");
						goto L1;
					} else if(strcmp(token, ".adr")==0) {
                        token=strtok(NULL, " ");
                        if(strcmp(token, "stdout")==0) printf("address of stdout: %p", (void*)stdout);
                        else if(strcmp(token, "stdin")==0) printf("address of stdin: %p", (void*)stdin);
                        else if(strcmp(token, "stderr")==0) printf("address of stderr: %p", (void*)stderr);

						puts("\n");
                        goto L1;
                    }
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
