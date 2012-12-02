#include <linux/init.h>
//#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h> // printk
#include <linux/slab.h>   // kmalloc
#include <linux/fs.h>     // everything
#include <linux/errno.h>  // errno
#include <linux/types.h>  //size_t
#include <linux/proc_fs.h>
#include <linux/fcntl.h>  // O_ACCMODE
#include <asm/system.h>   // cli()
#include <asm/uaccess.h>  // copy_from/to_user

MODULE_LICENSE("Dual BSD/GPL");

// declaration of memory.c functions
int memory_open(struct inode *inode, struct file *filp);
int memory_release(struct inode *inode, struct file *filp);
ssize_t memory_read(struct file *filp, char *buf, size_t count, loff_t *f_pos);
ssize_t memory_write(struct file *filp, char *buf, size_t count, loff_t *f_pos);
void memory_exit(void);
int memory_init(void);

// Structure that declares the usual file access file
struct file_operations memory_fops = {
    read: memory_read,
    write: memory_write,
    open: memory_open,
    release: memory_release
};

module_init(memory_init);
module_exit(memory_exit);

// Global variables of the driver
int memory_major = 60;
// Buffer to store data
char *memory_buffer;

int
memory_init(void)
{
    int result;

    result = register_chrdev(memory_major, "memory", &memory_fops);
    if(result < 0) {
        printk("<1>memory: cannot obtain major number %d\n", memory_major);
        return result;
    }

    memory_buffer = kmalloc(1, GFP_KERNEL);
    if(!memory_buffer) {
        result = -ENOMEM;
        goto fail;
    }
    memset(memory_buffer, 0, 1);

    printk("<1>Inserting memory module\n");
    return 0;

fail:
    memory_exit();
    return result;
}

void
memory_exit(void)
{
    unregister_chrdev(memory_major, "memory");

    // free the buffer memory
    if(memory_buffer)
        kfree(memory_buffer);

    printk("<1>Removing memory module\n");
}

int
memory_open(struct inode *inode, struct file *filp)
{
    // Success
    return 0;
}

int
memory_release(struct inode *inode, struct file *filp)
{
    // success
    return 0;
}

ssize_t
memory_read(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
    // Transfering data to user space
    copy_to_user(buf, memory_buffer, 1);

    if(*f_pos == 0) {
        *f_pos += 1;
        return 1;
    } else
        return 0;
}

ssize_t
memory_write(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
    char *tmp;

    tmp = buf + count - 1;
    copy_from_user(memory_buffer, tmp, 1);
    return 1;
}

