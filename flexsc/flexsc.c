#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/kthread.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/mman.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include <asm/processor.h>

#define MAX_ENTRY (64)
#define SYSCALL_ENTRY_FREE (0)
#define SYSCALL_ENTRY_SUBMITED (1)
#define SYSCALL_ENTRY_DONE (2)
#define SYSCALL_ENTRY_BLOCKED (3)

bool registerd = false;

extern void *mem_msg_buf;

extern asmlinkage long sys_mmap_pgoff(unsigned long addr, unsigned long len,
									  unsigned long prot, unsigned long flags,
									  unsigned long fd, unsigned long pgoff);

struct task_struct *task = NULL;

typedef struct {
	int syscall_num;
	short aug_num;
	short status;
	long ret_value;
	long arg0;
	long arg1;
	long arg2;
	long arg3;
	long arg4;
	long arg5;
} Syscall_entry;

typedef long (*sys_call_ptr_t)(long, long, long, long, long, long);


int do_syscall(void *addr) {
	Syscall_entry *syscall_page = (Syscall_entry *) addr;
	while (!kthread_should_stop()) {
		int i;
		for (i = 0; i < MAX_ENTRY; ++i) {
			if (syscall_page[i].status == SYSCALL_ENTRY_SUBMITED) {
				long ret;
				printk("REAL! Num: %d, Arguments: %ld, %ld, %ld, %ld, %ld, %ld\n",
					syscall_page[i].syscall_num,
					syscall_page[i].arg0,
					syscall_page[i].arg1,
					syscall_page[i].arg2,
					syscall_page[i].arg3,
					syscall_page[i].arg4,
					syscall_page[i].arg5);


				extern const sys_call_ptr_t sys_call_table[];
				ret = sys_call_table[syscall_page[i].syscall_num](syscall_page[i].arg0,
																  syscall_page[i].arg1,
																  syscall_page[i].arg2,
																  syscall_page[i].arg3,
																  syscall_page[i].arg4,
																  syscall_page[i].arg5);
		
				syscall_page[i].ret_value = ret;
				syscall_page[i].status = SYSCALL_ENTRY_DONE;
				printk("REAL ret value: %ld\n", ret);
			}
		}
		schedule();
	}
	return 0;
}

asmlinkage long sys_flexsc_register(void) {
	if (registerd) return 0;
	int i;
	Syscall_entry *syscall_page = mem_msg_buf;
	printk("DUMP SHARE MEMORY!\n");
	for (i = 0; i < MAX_ENTRY; ++i) {

			printk("%d, %ld, %ld, %ld, %ld, %ld, %ld, %d\n",
					syscall_page[i].syscall_num,
					syscall_page[i].arg0,
					syscall_page[i].arg1,
					syscall_page[i].arg2,
					syscall_page[i].arg3,
					syscall_page[i].arg4,
					syscall_page[i].arg5,
					(int)syscall_page[i].status);
	}

	task = kthread_create(&do_syscall, (void *)syscall_page, "flex: ");
	kthread_bind(task, 2);
	wake_up_process(task);
	registerd = true;
	if (!task) return -2;
/*
	Syscall_entry *syscall_page = (Syscall_entry *) kmalloc(MAX_ENTRY * sizeof(Syscall_entry), GFP_KERNEL);
	memset(syscall_page, 0, MAX_ENTRY * sizeof(Syscall_entry));
	unsigned long ret = copy_from_user(syscall_page, addr, MAX_ENTRY * sizeof(Syscall_entry));
	struct task_struct *task = kthread_run(&do_syscall, (void *)syscall_page, "flex: ");
	if (!task) return -1;
	*/
	return 0;
}

asmlinkage long sys_flexsc_cancel(void) {
	if (task) {
		 kthread_stop(task);
		 task = NULL;
		 registerd = false;
	}
	return 0;
}
