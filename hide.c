/*
	A small demo program that just hides itself from ps and exits
*/

#include <unistd.h>
#include <sys/syscall.h>

int main(int argc, char **argv) {
	syscall(216);
}
