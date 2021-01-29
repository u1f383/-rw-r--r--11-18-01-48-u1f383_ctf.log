#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<wait.h>

void initproc(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);
  return;
}

int main(){
  int JSLEN,cursor,res,fd,pid;
  char buf[10000];
  char tmpfile[32]="/tmp/jscode_XXXXXX";
  char *cargv[3];
  initproc();
  printf("javascript code length : ");
  scanf("%d",&JSLEN);
  getchar();
  if(JSLEN>10000||JSLEN<=0){
    puts("invalid code length");
    return 0;
  }
  while(cursor<JSLEN){
    res = read(STDIN_FILENO,&buf[cursor],1);
    if(res<=0){
      puts("read failed");
      return 0;
    }
    cursor+=1;
  }
  fd = mkstemp(tmpfile);
  if(fd<0){
    puts("tmpfile creation failed");
    return 0;
  }
  if(write(fd,buf,JSLEN)!=JSLEN){
    puts("write tmpfile failed");
    return 0;
  }
  pid = fork();
  if(pid<0){
    puts("fork failed");
    return 0;
  }
  else if(pid==0){
    cargv[0] = "/home/MuJS/mujs";
    cargv[1] = tmpfile;
    cargv[2] = NULL;
    execve(cargv[0],cargv,NULL);
  }
  else{
    res = waitpid(pid,NULL,0);
    remove(tmpfile);
  }
  return 0;
}
