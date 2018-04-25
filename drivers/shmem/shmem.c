#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h> /* register_chrdev, unregister_chrdev */
#include <linux/module.h>
#include <linux/seq_file.h> /* seq_read, seq_lseek, single_release */
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <linux/debugfs.h>

#define NAME "shmem"

static int major = -1;
static struct cdev mycdev;
static struct class *myclass = NULL;


void *mem_msg_buf = NULL;
EXPORT_SYMBOL(mem_msg_buf);


static int mem_mmap(struct file *filp, struct vm_area_struct *vma){
    unsigned long offset, physics, mypfn, vmsize, psize;
    printk("in mem_mmap\n");
    offset = vma->vm_pgoff << PAGE_SHIFT;
    physics = ((unsigned long )mem_msg_buf)-PAGE_OFFSET;
    mypfn = physics >> PAGE_SHIFT;
    vmsize = vma->vm_end-vma->vm_start;
    psize = (1 << PAGE_SHIFT) - offset;
    if(vmsize > psize)
    {
        printk("error: vmsize < psize\n");
        return -ENXIO;
    }
    if(remap_pfn_range(vma,vma->vm_start,mypfn,vmsize,vma->vm_page_prot))
    {
        printk("error: remap error!\n");
        return -EAGAIN;
    }
    return 0;
}


static const struct file_operations fops = {
    .mmap = mem_mmap,
};

static void *malloc_reserved_page(void){
    void *p = kmalloc(1 << PAGE_SHIFT, GFP_KERNEL);
    memset(p, 0, 1 << PAGE_SHIFT);
    if (!p){
        printk("Error : malloc_reserved_mem kmalloc failed!\n");
        return NULL;
    }
    SetPageReserved(virt_to_page(p));
    return p;
}

static void cleanup(int device_created)
{
    if (device_created) {
        device_destroy(myclass, major);
        cdev_del(&mycdev);
    }
    if (myclass)
        class_destroy(myclass);
    if (major != -1)
        unregister_chrdev_region(major, 1);
}

static int memDev_init(void){
    int device_created = 0;
    mem_msg_buf = malloc_reserved_page();

    /* cat /proc/devices */
    if (alloc_chrdev_region(&major, 0, 1, NAME "_proc") < 0)
        goto error;
    /* ls /sys/class */
    if ((myclass = class_create(THIS_MODULE, NAME "_sys")) == NULL)
        goto error;
    /* ls /dev/ */
    if (device_create(myclass, NULL, major, NULL, NAME "_dev") == NULL)
        goto error;
    device_created = 1;
    cdev_init(&mycdev, &fops);
    if (cdev_add(&mycdev, major, 1) == -1)
        goto error;
    return 0;
error:
    printk("SHMEM: create device error!");
    cleanup(device_created);
    return -1;
}



static void myexit(void)
{
    cleanup(1);
}



module_init(memDev_init)
module_exit(myexit)
MODULE_LICENSE("GPL");