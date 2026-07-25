// kernel/patch/common/passport.c
#include <passport.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/rwlock.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/printk.h>

#define PASSPORT_HASH_BITS 8

struct passport_entry {
    pid_t pid;
    uid_t uid;          // 记录授权时的 UID，防止 PID 伪造
    struct hlist_node hlist;
};

static DEFINE_HASHTABLE(passport_table, PASSPORT_HASH_BITS);
static DEFINE_RWLOCK(passport_lock);

/* ===== 核心检查函数 ===== */
int has_passport(struct task_struct *task)
{
    pid_t pid = task->pid;
    uid_t uid = task->uid;
    struct passport_entry *entry;
    int found = 0;

    read_lock(&passport_lock);
    hash_for_each_possible(passport_table, entry, hlist, pid) {
        if (entry->pid == pid && entry->uid == uid) {
            found = 1;
            break;
        }
    }
    read_unlock(&passport_lock);
    return found;
}
EXPORT_SYMBOL(has_passport);

/* ===== 添加 PID（内部使用，同时记录 UID） ===== */
static int add_passport_entry(pid_t pid, uid_t uid)
{
    struct passport_entry *entry;

    read_lock(&passport_lock);
    struct passport_entry *exist;
    hash_for_each_possible(passport_table, exist, hlist, pid) {
        if (exist->pid == pid) {
            read_unlock(&passport_lock);
            return 0; // 已存在
        }
    }
    read_unlock(&passport_lock);

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) return -ENOMEM;

    entry->pid = pid;
    entry->uid = uid;
    write_lock(&passport_lock);
    hash_add(passport_table, &entry->hlist, pid);
    write_unlock(&passport_lock);

    return 0;
}

/* ===== 移除 PID（保留供调试） ===== */
int remove_passport_pid(pid_t pid)
{
    struct passport_entry *entry;
    int found = 0;

    write_lock(&passport_lock);
    hash_for_each_possible(passport_table, entry, hlist, pid) {
        if (entry->pid == pid) {
            hash_del(&entry->hlist);
            kfree(entry);
            found = 1;
            break;
        }
    }
    write_unlock(&passport_lock);
    return found ? 0 : -ENOENT;
}
EXPORT_SYMBOL(remove_passport_pid);

/* ===== 清空所有（调试） ===== */
void clear_passport(void)
{
    struct passport_entry *entry;
    struct hlist_node *tmp;
    int i;

    write_lock(&passport_lock);
    hash_for_each_safe(passport_table, i, tmp, entry, hlist) {
        hash_del(&entry->hlist);
        kfree(entry);
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

    // 格式：pid 或 pid:uid （简单版本，仅支持 pid）
    token = strtok(kbuf, " \t\n");
    while (token) {
        pid = simple_strtol(token, NULL, 10);
        if (pid > 0) {
            uid = current_uid();  // 记录当前写入进程的 UID
            add_passport_entry(pid, uid);
            pr_info("KPASS: added pid %d with uid %d\n", pid, uid);
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
    hash_for_each(passport_table, i, entry) {
        int sz = snprintf(tmp, sizeof(tmp), "pid=%d uid=%d ", entry->pid, entry->uid);
        if (total + sz >= PAGE_SIZE) break;
        memcpy(page + total, tmp, sz);
        total += sz;
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

static const struct proc_ops passport_fops = {
    .proc_read  = passport_read,
    .proc_write = passport_write,
};

/* ===== 初始化（带调试日志） ===== */
static int __init passport_init(void)
{
    pr_info("KPASS: passport_init called\n");
    if (!proc_create("myroot_passport", 0660, NULL, &passport_fops)) {
        pr_err("KPASS: proc_create failed\n");
        return -ENOMEM;
    }
    pr_info("KPASS: /proc/myroot_passport created successfully\n");
    return 0;
}

void init_passport(void)
{
    pr_info("KPASS: init_passport called\n");
    passport_init();
}
EXPORT_SYMBOL(init_passport);