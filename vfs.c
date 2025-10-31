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
#define PROC_MEM_NAME "mem"
#define SYS_NAME "vfs"

// O------------------------------------------------------------------------------O
// | Virtual File System Implementation                                           |
// O------------------------------------------------------------------------------O

struct ramfile {
	char name[32];
	char *data;
	size_t size;
	bool used;
	struct proc_dir_entry *proc_entry;
};

static struct ramfile fs[MAX_FILES];

// Create proc endpoint for each file
static ssize_t file_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    struct ramfile *f = pde_data(file_inode(file));
    if (!f || !f->used || !f->data) {
		printk(KERN_WARNING "vfs: did not read properly");
		return 0;
	}

	printk(KERN_INFO "vfs: file_proc_read called, f=%p\n", f);
	if (f) printk(KERN_INFO "vfs: reading file '%s' size=%zu\n", f->name, f->size);

    if (*ppos >= f->size) return 0;

    if (count > f->size - *ppos)
        count = f->size - *ppos;

    if (copy_to_user(buf, f->data + *ppos, count))
        return -EFAULT;

    *ppos += count;
    return count;
}

static struct proc_ops file_proc_ops = {
    .proc_read  = file_proc_read,
};


static int ramvfs_lookup(const char *name)
{
    for (int i = 0; i < MAX_FILES; i++)
        if (fs[i].used && strcmp(fs[i].name, name) == 0)
            return i;
    return -1;
}

static int ramvfs_create(const char* name) {
	int i;

	if (ramvfs_lookup(name) >= 0) {
        printk(KERN_WARNING "vfs: file '%s' already exists\n", name);
        return -EEXIST;
    }

	for (i = 0; i < MAX_FILES; i++) {
		if (!fs[i].used) {
			strncpy(fs[i].name, name, sizeof(fs[i].name));
			fs[i].data = kmalloc(MAX_FILE_SIZE, GFP_KERNEL);
			fs[i].size = 0;
			fs[i].used = true;
			fs[i].proc_entry = proc_create_data(fs[i].name, 0444, NULL, &file_proc_ops, &fs[i]);
			if (!fs[i].proc_entry) {
				kfree(fs[i].data);
				fs[i].used = false;
				printk(KERN_WARNING "vfs: Failed to create /proc/%s\n", name);
				return -ENOMEM;
			}
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

	if (fs[index].proc_entry)
        proc_remove(fs[index].proc_entry);
	
	kfree(fs[index].data);
	fs[index].used = false;
	printk(KERN_INFO "vfs: Deleted file '%s'\n", fs[index].name);
}

// O------------------------------------------------------------------------------O
// | Proc user interface                                                          |
// O------------------------------------------------------------------------------O

static struct proc_dir_entry *proc_dir;

static struct proc_dir_entry *proc_entry;
static struct proc_dir_entry *proc_mem_entry;

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

static ssize_t vfs_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
	char kbuf[MAX_INPUT];
	char cmd[16], filename[32];
	int id;

	if (count >= MAX_INPUT)
		count = MAX_INPUT - 1;

	if (copy_from_user(kbuf, buf, count))
        return -EFAULT;
    kbuf[count] = '\0';
	strim(kbuf);

	if (sscanf(kbuf, "%15s %31s %1023[^\n]", cmd, filename, kbuf) < 2) {
		printk(KERN_WARNING "ramvfs: Invalid input\n");
        return count;
	}
	
	if (strcmp(cmd, "create") == 0) {
		id = ramvfs_create(filename);
        if (id < 0)
			printk(KERN_WARNING "vfs: Failed to create file '%s'\n", filename);
	} else if (strcmp(cmd, "write") == 0) {
		id = ramvfs_lookup(filename);
		if (id >= 0) 
			ramvfs_write(id, kbuf, strlen(kbuf));
		else
			printk(KERN_WARNING "vfs: Failed to write to file '%s'\n", filename);
	} else if (strcmp(cmd, "delete") == 0) {
		id = ramvfs_lookup(filename);
		if (id >= 0)
			ramvfs_delete(id);
		else
			printk(KERN_WARNING "vfs: Failed to delete file '%s'\n", filename);
	} else {
		printk(KERN_WARNING "vfs: Unknown command '%s'\n", cmd);
	}

	return count;
}

static const struct proc_ops vfs_proc_ops = {
    .proc_read = vfs_proc_read,
	.proc_write = vfs_proc_write,
};

static ssize_t vfs_mem_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
	char kbuf[128];
    int total = 0;
    int i;
	int len;

    if (*ppos > 0) return 0;

    for (i = 0; i < MAX_FILES; i++) {
        if (fs[i].used)
			total += fs[i].size;
	}
	
	len = snprintf(kbuf, sizeof(kbuf), "Total RAM used: %d bytes\n", total);

    if (copy_to_user(buf, kbuf, len))
        return -EFAULT;

    *ppos = len;
    return len;
}

static const struct proc_ops vfs_mem_ops = {
	.proc_read = vfs_mem_read,
};

// O------------------------------------------------------------------------------O
// | Sys user interface                                                           |
// O------------------------------------------------------------------------------O

static struct kobject *ramvfs_kobj;
static struct kobject *ramvfs_max_kobj;

static ssize_t num_files_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	int i = 0;
	int count = 0;
	for (i = 0; i < MAX_FILES; i++)
		if (fs[i].used) count++;
	
	return sprintf(buf, "%d\n", count);
}

static struct kobj_attribute num_files_attr = __ATTR(num_files, 0444, num_files_show, NULL);

static ssize_t max_files_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	return sprintf(buf, "%d\n", MAX_FILES);
}

static struct kobj_attribute max_files_attr = __ATTR(max_files, 0444, max_files_show, NULL);

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

	//proc init 
	proc_dir = proc_mkdir("vfs", NULL);
    if (!proc_dir) {
        printk(KERN_ALERT "vfs: Failed to create /proc/vfs\n");
        return -ENOMEM;
    }

	proc_entry = proc_create(PROC_NAME, 0444, NULL, &vfs_proc_ops);
	if (!proc_entry) {
		printk(KERN_ALERT "vfs: Failed to create /proc/%s\n", PROC_NAME);
    	return -ENOMEM;
	}
	printk(KERN_INFO "vfs: /proc/%s created\n", PROC_NAME);
	proc_mem_entry = proc_create(PROC_MEM_NAME, 0444, NULL, &vfs_mem_ops);
	if (!proc_mem_entry) {
		printk(KERN_ALERT "vfs: Failed to create /proc/%s\n", PROC_MEM_NAME);
    	return -ENOMEM;
	}
	printk(KERN_INFO "vfs: /proc/%s created\n", PROC_MEM_NAME);

	//sys init
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

	sys_ret = sysfs_create_file(ramvfs_kobj, &max_files_attr.attr);
	if (sys_ret) {
		printk(KERN_ALERT "vfs: Failed to create /sys/%s/max_files\n", SYS_NAME);
    	return -ENOMEM;
	}
    printk(KERN_INFO "vfs: /sys/%s/num_files attribute created\n", SYS_NAME);

	//test file creation
	id = ramvfs_create("hello.txt");
    if (id >= 0) {
        ramvfs_write(id, "Hello, kernel world!", 20);
        ramvfs_read(id, read_buf, 20);
        printk(KERN_INFO "ramvfs: Read data = '%s'\n", read_buf);
    }

	id2 = ramvfs_create("hello2.txt");
	ramvfs_delete(id2);

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
	proc_remove(proc_mem_entry);
	printk(KERN_INFO "vfs: /proc/%s removed\n", PROC_MEM_NAME);

	kobject_put(ramvfs_kobj);
	kobject_put(ramvfs_max_kobj);
	printk(KERN_INFO "vfs: /sys/%s removed\n", SYS_NAME);
}

module_init(vfs_init);
module_exit(vfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("froggo");
MODULE_DESCRIPTION("Virtual filesystem kernel");
MODULE_VERSION("1.0");
