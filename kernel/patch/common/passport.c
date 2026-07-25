// kernel/patch/common/passport.c
#include <passport.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/cred.h>
#include <asm/current.h>

#define PASSPORT_HASH_BITS 8
#define PASSPORT_HASH_SIZE (1 << PASSPORT_HASH_BITS)

struct passport_entry {
    int pid;
    uid_t uid;
    struct list_head list;
};

static struct list_head passport_table[PASSPORT_HASH_SIZE];
static DEFINE_SPINLOCK(passport_lock);

static inline unsigned int passport_hash(int pid)
{
    return pid & (PASSPORT_HASH_SIZE - 1);
}

int has_passport(void)
{
    int pid = current->pid;
    uid_t uid = current_uid();
    struct passport_entry *entry;
    int found = 0;
    unsigned int hash = passport_hash(pid);

    spin_lock(&passport_lock);
    list_for_each_entry(entry, &passport_table[hash], list) {
        if (entry->pid == pid && entry->uid == uid) {
            found = 1;
            break;
        }
    }
    spin_unlock(&passport_lock);

    if (found)
        pr_info("KPASS: pid %d uid %d PASS\n", pid, uid);
    else
        pr_info("KPASS: pid %d uid %d DENIED\n", pid, uid);

    return found;
}

/* 临时测试用：硬编码添加一个 PID（后续替换为 Netlink） */
void init_passport(void)
{
    int i;
    for (i = 0; i < PASSPORT_HASH_SIZE; i++)
        INIT_LIST_HEAD(&passport_table[i]);

    /* 硬编码测试：把当前进程（init 或 shell）加入白名单 */
    // 这里先空着，我们可以在需要时用 add_passport_entry 手动添加

    pr_info("KPASS: passport module initialized (hash table ready)\n");
}
