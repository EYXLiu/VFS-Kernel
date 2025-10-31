#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#define MAX_FILES 10
#define MAX_FILE_SIZE 1024

#define PROC_NAME "vfs"
#define SYS_NAME "vfs"

// O------------------------------------------------------------------------------O
// | Virtual File System Implementation                                           |
// O------------------------------------------------------------------------------O

struct ramfile {
	char name[32];
	char *data;
	size_t size;
	bool used;
};

static struct ramfile fs[MAX_FILES];

static int ramvfs_create(const char* name) {
	int i;
	for (i = 0; i < MAX_FILES; i++) {
		if (!fs[i].used) {
			strncpy(fs[i].name, name, sizeof(fs[i].name));
			fs[i].data = kmalloc(MAX_FILE_SIZE, GFP_KERNEL);
			fs[i].size = 0;
			fs[i].used = true;
			printk(KERN_INFO "vfs: Created file '%s'\n", name);
			return i;
		}
	}
	printk(KERN_WARNING "vfs: No free slots avaliable to create file '%s'\n", name);
	return -1;
}

static ssize_t ramvfs_write(int index, const char *data, size_t len) {
	if (index < 0 || index >= MAX_FILES || !fs[index].used)
		return -EINVAL;
	
	if (len > MAX_FILE_SIZE) {
        len = MAX_FILE_SIZE;
	}
	
	memcpy(fs[index].data, data, len);
	fs[index].size = len;
	printk(KERN_INFO "vfs: Wrote %zu bytes to '%s'\n", len, fs[index].name);
	return len;
}

static ssize_t ramvfs_read(int index, char *buf, size_t len) {
	if (index < 0 || index >= MAX_FILES || !fs[index].used)
        return -EINVAL;

    if (len > fs[index].size) {
        len = fs[index].size;
	}
	
	memcpy(buf, fs[index].data, len);

	if (len < fs[index].size)
		buf[len] = '\0';
	else
		buf[fs[index].size - 1] = '\0';
	
	printk(KERN_INFO "vfs: Read %zu bytes from '%s'\n", len, fs[index].name);
	return len;
}

static void ramvfs_delete(int index) {
	if (index < 0 || index >= MAX_FILES || !fs[index].used)
        return;
	
	kfree(fs[index].data);
	fs[index].used = false;
	printk("vfs: Deleted file '%s'\n", fs[index].name);
}

// O------------------------------------------------------------------------------O
// | Proc user interface                                                          |
// O------------------------------------------------------------------------------O

static struct proc_dir_entry *proc_entry;

static ssize_t vfs_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
	int i;
	int len = 0;
	char kbuf[512];

	if (*ppos > 0)
		return 0;
	
	for (i = 0; i < MAX_FILES; i++) {
        if (fs[i].used) {
            len += snprintf(kbuf + len, sizeof(kbuf) - len, "%s (size: %zu)\n", fs[i].name, fs[i].size);
        }
    }

	if (copy_to_user(buf, kbuf, len))
        return -EFAULT;

	*ppos = len;
	return len;
}

static const struct proc_ops vfs_proc_ops = {
    .proc_read = vfs_proc_read,
};

// O------------------------------------------------------------------------------O
// | Sys user interface                                                           |
// O------------------------------------------------------------------------------O

static struct kobject *ramvfs_kobj;

static ssize_t num_files_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	int i = 0;
	int count = 0;
	for (i = 0; i < MAX_FILES; i++)
		if (fs[i].used) count++;
	
	return sprintf(buf, "%d\n", count);
}

static struct kobj_attribute num_files_attr = __ATTR(num_files, 0444, num_files_show, NULL);

// O------------------------------------------------------------------------------O
// | Kernel INIT and EXIT                                                         |
// O------------------------------------------------------------------------------O

static int __init vfs_init(void) {
	int i;
	int id;
	int id2;
	char read_buf[64];

	int sys_ret;
	
	//init filesystem
	for (i = 0; i < MAX_FILES; i++) {
		fs[i].used = false;
		fs[i].data = NULL;
	}
	printk(KERN_INFO "vfs: Initialized RAM filesystem with %d slots\n", MAX_FILES);

	//test file creation
	id = ramvfs_create("hello.txt");
    if (id >= 0) {
        ramvfs_write(id, "Hello, kernel world!", 20);
        ramvfs_read(id, read_buf, 20);
        printk(KERN_INFO "ramvfs: Read data = '%s'\n", read_buf);
    }

	id2 = ramvfs_create("hello2.txt");
	ramvfs_delete(id2);

	//test proc 
	proc_entry = proc_create(PROC_NAME, 0444, NULL, &vfs_proc_ops);
	if (!proc_entry) {
		printk(KERN_ALERT "vfs: Failed to create /proc/%s\n", PROC_NAME);
    	return -ENOMEM;
	}
	printk(KERN_INFO "vfs: /proc/%s created\n", PROC_NAME);

	//test sys
	ramvfs_kobj = kobject_create_and_add(SYS_NAME, kernel_kobj);
	if (!ramvfs_kobj) {
		printk(KERN_ALERT "vfs: Failed to create /sys/%s\n", SYS_NAME);
    	return -ENOMEM;
	}
	sys_ret = sysfs_create_file(ramvfs_kobj, &num_files_attr.attr);
	if (sys_ret) {
		printk(KERN_ALERT "vfs: Failed to create /sys/%s/num_files\n", SYS_NAME);
    	return -ENOMEM;
	}
    printk(KERN_INFO "vfs: /sys/%s/num_files attribute created\n", SYS_NAME);

	return 0;
}

static void __exit vfs_exit(void) {
	int i;
	for (i = 0; i < MAX_FILES; i++) {
		if (fs[i].used && fs[i].data) 
			kfree(fs[i].data);
	}
	printk(KERN_INFO "vfs: Module unloaded, memory freed\n");

	proc_remove(proc_entry);
	printk(KERN_INFO "vfs: /proc/%s removed\n", PROC_NAME);

	kobject_put(ramvfs_kobj);
	printk(KERN_INFO "vfs: /sys/%s removed\n", PROC_NAME);
}

module_init(vfs_init);
module_exit(vfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("froggo");
MODULE_DESCRIPTION("Virtual filesystem kernel");
MODULE_VERSION("1.0");
