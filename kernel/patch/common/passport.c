// kernel/patch/common/passport.c
#include <passport.h>
#include <linux/slab.h>
#include <linux/rwlock.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/proc_fs.h>      // 有些版本需要这个，但我们不使用 proc_create，但仍需要它的类型定义
#include <linux/fs.h>           // 提供 struct file_operations

#define PASSPORT_HASH_BITS 8
#define PASSPORT_HASH_SIZE (1 << PASSPORT_HASH_BITS)

struct passport_entry {
    pid_t pid;
    uid_t uid;
    struct list_head list;
};

static struct list_head passport_table[PASSPORT_HASH_SIZE];
static DEFINE_RWLOCK(passport_lock);
static struct proc_dir_entry *passport_proc_entry;

static inline unsigned int passport_hash(pid_t pid)
{
    return pid & (PASSPORT_HASH_SIZE - 1);
}

/* ===== 核心检查函数 ===== */
int has_passport(struct task_struct *task)
{
    pid_t pid = task->pid;
    uid_t uid = task->uid;
    struct passport_entry *entry;
    int found = 0;
    unsigned int hash = passport_hash(pid);

    read_lock(&passport_lock);
    list_for_each_entry(entry, &passport_table[hash], list) {
        if (entry->pid == pid && entry->uid == uid) {
            found = 1;
            break;
        }
    }
    read_unlock(&passport_lock);
    return found;
}
EXPORT_SYMBOL(has_passport);

/* ===== 添加 PID ===== */
static int add_passport_entry(pid_t pid, uid_t uid)
{
    struct passport_entry *entry;
    unsigned int hash = passport_hash(pid);

    read_lock(&passport_lock);
    list_for_each_entry(entry, &passport_table[hash], list) {
        if (entry->pid == pid && entry->uid == uid) {
            read_unlock(&passport_lock);
            return 0;
        }
    }
    read_unlock(&passport_lock);

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) return -ENOMEM;

    entry->pid = pid;
    entry->uid = uid;
    write_lock(&passport_lock);
    list_add(&entry->list, &passport_table[hash]);
    write_unlock(&passport_lock);

    pr_info("KPASS: added pid %d uid %d\n", pid, uid);
    return 0;
}

/* ===== 移除 PID ===== */
int remove_passport_pid(pid_t pid)
{
    struct passport_entry *entry;
    int found = 0;
    unsigned int hash = passport_hash(pid);

    write_lock(&passport_lock);
    list_for_each_entry(entry, &passport_table[hash], list) {
        if (entry->pid == pid) {
            list_del(&entry->list);
            kfree(entry);
            found = 1;
            break;
        }
    }
    write_unlock(&passport_lock);
    return found ? 0 : -ENOENT;
}
EXPORT_SYMBOL(remove_passport_pid);

/* ===== 清空所有 ===== */
void clear_passport(void)
{
    struct passport_entry *entry, *tmp;
    int i;

    write_lock(&passport_lock);
    for (i = 0; i < PASSPORT_HASH_SIZE; i++) {
        list_for_each_entry_safe(entry, tmp, &passport_table[i], list) {
            list_del(&entry->list);
            kfree(entry);
        }
    }
    write_unlock(&passport_lock);
}
EXPORT_SYMBOL(clear_passport);

/* ===== proc 文件接口 ===== */

static ssize_t passport_write(struct file *file, const char __user *buf,
                              size_t len, loff_t *off)
{
    char *kbuf;
    char *token;
    int ret = 0;
    pid_t pid;
    uid_t uid;

    if (len > PAGE_SIZE) len = PAGE_SIZE;
    kbuf = kmalloc(len + 1, GFP_KERNEL);
    if (!kbuf) return -ENOMEM;

    if (copy_from_user(kbuf, buf, len)) {
        ret = -EFAULT;
        goto out;
    }
    kbuf[len] = '\0';

    token = strtok(kbuf, " \t\n");
    while (token) {
        pid = simple_strtol(token, NULL, 10);
        if (pid > 0) {
            uid = current_uid();
            add_passport_entry(pid, uid);
        }
        token = strtok(NULL, " \t\n");
    }
    ret = len;

out:
    kfree(kbuf);
    return ret;
}

static ssize_t passport_read(struct file *file, char __user *buf,
                             size_t len, loff_t *off)
{
    struct passport_entry *entry;
    char tmp[64];
    int total = 0;
    int i;
    char *page = (char *)__get_free_page(GFP_KERNEL);
    if (!page) return -ENOMEM;

    read_lock(&passport_lock);
    for (i = 0; i < PASSPORT_HASH_SIZE; i++) {
        list_for_each_entry(entry, &passport_table[i], list) {
            int sz = snprintf(tmp, sizeof(tmp), "pid=%d uid=%d ", entry->pid, entry->uid);
            if (total + sz >= PAGE_SIZE) break;
            memcpy(page + total, tmp, sz);
            total += sz;
        }
    }
    read_unlock(&passport_lock);

    if (total > 0) {
        page[total-1] = '\n';
    } else {
        page[0] = '\n';
        total = 1;
    }

    if (*off >= total) {
        free_page((unsigned long)page);
        return 0;
    }
    if (len > total - *off) len = total - *off;
    if (copy_to_user(buf, page + *off, len)) {
        free_page((unsigned long)page);
        return -EFAULT;
    }
    *off += len;
    free_page((unsigned long)page);
    return len;
}

static const struct file_operations passport_fops = {
    .read  = passport_read,
    .write = passport_write,
};

/* ===== 初始化 ===== */
static int __init passport_init(void)
{
    int i;

    pr_info("KPASS: passport_init called\n");

    for (i = 0; i < PASSPORT_HASH_SIZE; i++)
        INIT_LIST_HEAD(&passport_table[i]);

    // 使用 create_proc_entry 替代 proc_create
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    passport_proc_entry = proc_create("myroot_passport", 0660, NULL, &passport_fops);
#else
    passport_proc_entry = create_proc_entry("myroot_passport", 0660, NULL);
    if (passport_proc_entry)
        passport_proc_entry->proc_fops = &passport_fops;
#endif

    if (!passport_proc_entry) {
        pr_err("KPASS: failed to create /proc/myroot_passport\n");
        return -ENOMEM;
    }

    pr_info("KPASS: /proc/myroot_passport created\n");
    return 0;
}

void init_passport(void)
{
    pr_info("KPASS: init_passport called\n");
    passport_init();
}
EXPORT_SYMBOL(init_passport);
