// kernel/patch/common/passport.c
#include <passport.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/rwlock.h>
#include <linux/list.h>
#include <linux/sched.h>

#define PASSPORT_HASH_BITS 8
#define PASSPORT_HASH_SIZE (1 << PASSPORT_HASH_BITS)

struct passport_entry {
    pid_t pid;
    uid_t uid;
    struct list_head list;
};

static struct list_head passport_table[PASSPORT_HASH_SIZE];
static DEFINE_RWLOCK(passport_lock);

static inline unsigned int passport_hash(pid_t pid)
{
    return pid & (PASSPORT_HASH_SIZE - 1);
}

/* 添加通行证 */
static int add_passport_entry(pid_t pid, uid_t uid)
{
    struct passport_entry *entry;
    unsigned int hash = passport_hash(pid);

    // 检查是否已存在（避免重复）
    read_lock(&passport_lock);
    list_for_each_entry(entry, &passport_table[hash], list) {
        if (entry->pid == pid && entry->uid == uid) {
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
    list_add(&entry->list, &passport_table[hash]);
    write_unlock(&passport_lock);

    pr_info("KPASS: added passport for pid=%d uid=%d\n", pid, uid);
    return 0;
}

/* 移除通行证（供未来使用） */
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
            pr_info("KPASS: removed passport for pid=%d\n", pid);
            break;
        }
    }
    write_unlock(&passport_lock);
    return found ? 0 : -ENOENT;
}
EXPORT_SYMBOL(remove_passport_pid);

/* 清空所有（调试/卸载用） */
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
    pr_info("KPASS: cleared all passports\n");
}
EXPORT_SYMBOL(clear_passport);

/* 核心检查函数：验证进程是否有通行证 */
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

    if (found)
        pr_debug("KPASS: pid %d uid %d PASS\n", pid, uid);
    else
        pr_debug("KPASS: pid %d uid %d DENIED\n", pid, uid);

    return found;
}
EXPORT_SYMBOL(has_passport);

/* 初始化（在 su_compat_init 中调用） */
void init_passport(void)
{
    int i;
    for (i = 0; i < PASSPORT_HASH_SIZE; i++)
        INIT_LIST_HEAD(&passport_table[i]);

    pr_info("KPASS: passport module initialized (hash table ready)\n");
}
EXPORT_SYMBOL(init_passport);

/* ===== 临时调试接口（通过 /proc 手动添加 PID，仅开发用） ===== */
/* 此部分将在 Netlink 实现后移除或保留作为备用 */
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

static ssize_t debug_write(struct file *file, const char __user *buf,
                           size_t len, loff_t *off)
{
    char kbuf[32];
    pid_t pid;
    uid_t uid = current_uid();

    if (len > sizeof(kbuf)-1) len = sizeof(kbuf)-1;
    if (copy_from_user(kbuf, buf, len)) return -EFAULT;
    kbuf[len] = '\0';

    pid = simple_strtol(kbuf, NULL, 10);
    if (pid <= 0) return -EINVAL;

    add_passport_entry(pid, uid);
    return len;
}

static const struct proc_ops debug_fops = {
    .proc_write = debug_write,
};

static void __init create_debug_proc(void)
{
    struct proc_dir_entry *entry = proc_create("passport_debug", 0220, NULL, &debug_fops);
    if (entry)
        pr_info("KPASS: debug proc /proc/passport_debug created (write PID to add)\n");
    else
        pr_err("KPASS: failed to create debug proc\n");
}

/* 在 init_passport 中调用 create_debug_proc() 可临时启用调试接口，
   但为了隐蔽性，默认注释掉，需要时取消注释 */
// create_debug_proc();
