#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#define TIMEOUT 60

void handler(int signum){
	puts("Timeout");
	_exit(1);
} 

void init_proc(){
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	signal(SIGALRM,handler);
	alarm(TIMEOUT);
} 

long long read_long(){
	char buf[24];
	long long choice ;
	__read_chk(0,buf,23,24);
	choice = atoll(buf);
	return choice;
}
 
void read_input(char *buf,unsigned int size){
	int ret ;
	ret = __read_chk(0,buf,size,size);
	if(ret <= 0){
		puts("read error");
		_exit(1);
	}
	if(buf[ret-1] == '\n')
		buf[ret-1] = '\x00';
}

char name[0x20];
char *heap[5];
bool is_free = false;

void allocate(){
	size_t size ;
	for(int i = 0 ; i < 5 ; i++){
		if(!heap[i]){
			printf("Size:");
			size = read_long();
			if(size < 0x78 || size > 0x1000){
				puts("too small or large");
				exit(-2);
			}
			heap[i] = malloc(size);
			if(!heap[i]){
				puts("Error!");	
			}
			return ;
		}
	}
	puts("Too more !");
}

void dfree(){
	unsigned int idx = 0 ;
	printf("Index:");
	idx = read_long();
	if(idx < 5){
		free(heap[idx]);
		heap[idx] = NULL ;	
	}else{
		puts("Too large");
	}
}

void edit(){
	unsigned int idx = 0 ;
	size_t size = 0 ;
	printf("Index:");
	idx = read_long();
	if(idx < 5){
		printf("Size:");
		size = read_long();
		printf("Data:");
		read_input(heap[idx],size);
	}else{
		puts("Too large");
	}
}

void show(){
	unsigned int idx = 0 ;
	printf("Index:");
	idx = read_long();
	
	if(idx < 5){
		if(heap[idx]){
			printf("Name:%s\n",name);
			printf("Content:%s\n",heap[idx]);
		}
	}else{
		puts("Too large");
	}
}

void menu(){
	puts("*************************");
	puts("     Magic Allocator     ");
	puts("*************************");
	puts(" 1. Alloc                ");
	puts(" 2. Free                 ");
	puts(" 3. Edit                 ");
	puts(" 4. Show                 ");
	puts(" 3. Exit                 ");
	puts("*************************");
	printf("Your choice:");
}


int main(){
	init_proc();
	printf("Name:");
	read_input(name,0x20);
	while(1){
		menu();
		switch(read_long()){
			case 1 :
				allocate();
				break ;
			case 2 :
				if(!is_free)
					dfree();
				else{
					puts("No more free !");
				}
				is_free = true;
				break ;
			case 3 :
				edit();
				break;
			case 4:
				show();
				break;
			case 5 :
				exit(0);
				break ;
			default :
				puts("Invalid choice");
				break;
		}
	}
}





