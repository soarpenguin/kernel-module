/* simple_entry.c
 *
 * This program provides an example of how to install an entry into the
 *   /proc File System.  All this entry does is display some statistical
 *   information about IP.
 */

#define MODULE
#include <linux/module.h>
/* proc_fs.h contains proc_dir_entry and register/unregister prototypes */
#include <linux/proc_fs.h>
/* ip.h contains the ip_statistics variable */
#include <net/ip.h>


/************************************************************ show_ip_stats
 * this function is what the /proc FS will call when anything tries to read
 *   from the file /proc/simple_entry - it puts some of the kernel global
 *   variable ip_statistics's contents into the return buffer */
int show_ip_stats(char *buf,char **start,off_t offset,int len,int unused) {
  len = sprintf(buf,"Some IP Statistics:\nIP Forwarding is ");
  if (ip_statistics.IpForwarding)
    len += sprintf(buf+len,"on\n");
  else
    len += sprintf(buf+len,"off\n");
  len += sprintf(buf+len,"Default TTL:  %lu\n",ip_statistics.IpDefaultTTL);
  len += sprintf(buf+len,"Frag Creates: %lu\n",ip_statistics.IpFragCreates);
  /* this could show more.... */
  return len;
}  /* show_ip_stats */

/**************************************************************** test_entry
 * this structure is a sort of registration form for the /proc FS; it tells
 *   the FS to allocate a dynamic inode, gives the "file" a name, and gives
 *   the address of a function to call when the file is read  */
struct proc_dir_entry test_entry = {
  0,                     /* low_ino - inode number (0 for dynamic)  */
  12,                    /* namelen - length of entry name          */
  "simple_entry",        /* name                                    */
  S_IFREG | S_IRUGO,     /* mode                                    */
  1,                     /* nlinks                                  */
  0,                     /* uid - owner                             */
  0,                     /* gid - group                             */
  0,                     /* size - not used                         */
  NULL,                  /* ops - inode operations (use default)    */
  &show_ip_stats         /* read_proc - address of read function    */
                         /* leave rest blank!                       */
};

/*************************************************************** init_module
 * this function installs the module; it simply registers a directory entry
 *   with the /proc FS  */
int init_module() {
  /* register the function with the proc FS */
  int err = proc_register(&proc_root,&test_entry);
  /* put the registration results in the log */
  if (!err)
    printk("<1> simple_entry: registered with inode %d.\n",
          test_entry.low_ino);
  else
    printk("<1> simple_entry: registration error, code %d.\n",err);
  return err;
}  /* init_module */

/************************************************************ cleanup_module
 * this function removes the module; it simply unregisters the directory
 *   entry from the /proc FS  */
void cleanup_module() {
  /* unregister the function from the proc FS */
  int err = proc_unregister(&proc_root,test_entry.low_ino);
  /* put the unregistration results in the log */
  if (!err)
    printk("<1> simple_entry: unregistered inode %d.\n",
          test_entry.low_ino);
  else
    printk("<1> simple_entry: unregistration error, code %d.\n",err);
}  /* cleanup_module */



/***********************************************************
# Makefile for simple_entry
CC = gcc -I/usr/src/linux/include
CFLAGS = -O2 -D__KERNEL__ -Wall

simple_entry.o: simple_entry.c

install:
    /sbin/insmod simple_entry

remove:
    /sbin/rmmod simple_entry
***********************************************************/
