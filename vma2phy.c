/*
 *  mtest_dump_vma_list（）：打印出当前进程的各个VMA，这个功能我们简称"listvma"
 *  mtest_find_vma()： 找出某个虚地址所在的VMA，这个功能我们简称"findvma"
 *  my_follow_page( )：根据页表，求出某个虚地址所在的物理页面，这个功能我们简称"findpage"
 *  mtest_write_val(), 在某个地址写上具体数据，这个功能我们简称"writeval".
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/highmem.h>

MODULE_LICENSE("GPL");

/*
 *  @如何编写代码查看自己的进程到底有哪些虚拟区？
 */
static void mtest_dump_vma_list(void)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	printk("The current process is %s\n",current->comm);
	printk("mtest_dump_vma_list\n");
	down_read(&mm->mmap_sem);
	for (vma = mm->mmap;vma; vma = vma->vm_next) {
		printk("VMA 0x%lx-0x%lx ",
				vma->vm_start, vma->vm_end);
		if (vma->vm_flags & VM_WRITE)
			printk("WRITE ");
		if (vma->vm_flags & VM_READ)
			printk("READ ");
		if (vma->vm_flags & VM_EXEC)
			printk("EXEC ");
		printk("\n");
	}
	up_read(&mm->mmap_sem);
}

/*
 *  @如果知道某个虚地址，比如，0×8049000,
 *  又如何找到这个地址所在VMA是哪个？
 */
static void  mtest_find_vma(unsigned long addr)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	printk("mtest_find_vma\n");
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, addr);
	if (vma && addr >= vma->vm_start) {
		printk("found vma 0x%lx-0x%lx flag %lx for addr 0x%lx\n",
				vma->vm_start, vma->vm_end, vma->vm_flags, addr);
	} else {
		printk("no vma found for %lx\n", addr);
	}
	up_read(&mm->mmap_sem);
}

/*
 *  @一个物理页在内核中用struct page来描述。
 *  给定一个虚存区VMA和一个虚地址addr，
 *  找出这个地址所在的物理页面page.
 */
static struct page *
my_follow_page(struct vm_area_struct *vma, unsigned long addr)
{
	pud_t *pud;
	pmd_t *pmd;
	pgd_t *pgd;
	pte_t *pte;
	spinlock_t *ptl;
	struct page *page = NULL;
	struct mm_struct *mm = vma->vm_mm;
	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
		goto out;
	}
	pud = pud_offset(pgd, addr);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		goto out;
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
		goto out;
	}
	pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	if (!pte)
		goto out;
	if (!pte_present(*pte))
		goto unlock;
	page = pfn_to_page(pte_pfn(*pte));
	if (!page)
		goto unlock;
	get_page(page);
unlock:
	pte_unmap_unlock(pte, ptl);
out:
	return page;
}

/*
 *  @ 根据页表，求出某个虚地址所在的物理页面，
 *  这个功能我们简称"findpage"
 */
static void   mtest_find_page(unsigned long addr)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long kernel_addr;
	struct page *page;
	printk("mtest_write_val\n");
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, addr);
	page = my_follow_page(vma, addr);
	if (!page)
	{
		printk("page not found  for 0x%lx\n", addr);
		goto out;
	}
	printk("page  found  for 0x%lx\n", addr);
	kernel_addr = (unsigned long)page_address(page);
	kernel_addr += (addr&~PAGE_MASK);
	printk("find  0x%lx to kernel address 0x%lx\n", addr, kernel_addr);
out:
	up_read(&mm->mmap_sem);
}

/*
 *  @你是否有这样的想法，
 *  给某个地址写入自己所想写的数据？
 */
static void
mtest_write_val(unsigned long addr, unsigned long val)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	struct page *page;
	unsigned long kernel_addr;
	printk("mtest_write_val\n");
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, addr);
	if (vma && addr >= vma->vm_start && (addr + sizeof(val)) < vma->vm_end) {
		if (!(vma->vm_flags & VM_WRITE)) {
			printk("vma is not writable for 0x%lx\n", addr);
			goto out;
		}
		page = my_follow_page(vma, addr);
		if (!page) {
			printk("page not found  for 0x%lx\n", addr);
			goto out;
		}
		kernel_addr = (unsigned long)page_address(page);
		kernel_addr += (addr&~PAGE_MASK);
		printk("write 0x%lx to address 0x%lx\n", val, kernel_addr);
		*(unsigned long *)kernel_addr = val;
		put_page(page);
	} else {
		printk("no vma found for %lx\n", addr);
	}
out:
	up_read(&mm->mmap_sem);
}

static ssize_t
mtest_write(struct file *file, const char __user * buffer,
		size_t count, loff_t * data)
{
	char buf[128];
	unsigned long val, val2;
	printk("mtest_write  ………..  \n");
	if (count > sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, buffer, count))
		return -EINVAL;
	if (memcmp(buf, "listvma", 7) == 0)
		mtest_dump_vma_list();
	else if (memcmp(buf, "findvma", 7) == 0) {
		if (sscanf(buf + 7, "%lx", &val) == 1) {
			mtest_find_vma(val);
		}
	}
	else if (memcmp(buf, "findpage", 8) == 0) {
		if (sscanf(buf + 8, "%lx", &val) == 1) {
			mtest_find_page(val);
			//my_follow_page(vma, addr);
		}
	}
	else  if (memcmp(buf, "writeval", 8) == 0) {
		if (sscanf(buf + 8, "%lx %lx", &val, &val2) == 2) {
			mtest_write_val(val, val2);
		}
	}
	return count;
}

static struct
file_operations proc_mtest_operations = {
	.write        = mtest_write
};


static struct proc_dir_entry *mtest_proc_entry;
//整个操作我们以模块的形式实现，因此，模块的初始化和退出函数如下：
static int __init
mtest_init(void)
{
	mtest_proc_entry = create_proc_entry("mtest", 0777, NULL);
	if (mtest_proc_entry == NULL) {
		printk("Error creating proc entry\n");
		return -1;
	}
	printk("create the filename mtest mtest_init sucess  \n");
	mtest_proc_entry->proc_fops = &proc_mtest_operations;
	return 0;
}

static void
__exit mtest_exit(void)
{
	printk("exit the module……mtest_exit \n");
	remove_proc_entry("mtest", NULL);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("mtest");
MODULE_AUTHOR("Zou Nan hai");
module_init(mtest_init);
module_exit(mtest_exit);

