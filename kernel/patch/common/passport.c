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

static int add_passport_entry(int pid, uid_t uid)
{
    struct passport_entry *entry;
    unsigned int hash = passport_hash(pid);

    spin_lock(&passport_lock);
    list_for_each_entry(entry, &passport_table[hash], list) {
        if (entry->pid == pid && entry->uid == uid) {
            spin_unlock(&passport_lock);
            return 0;
        }
    }
    spin_unlock(&passport_lock);

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) return -ENOMEM;

    entry->pid = pid;
    entry->uid = uid;
    spin_lock(&passport_lock);
    list_add(&entry->list, &passport_table[hash]);
    spin_unlock(&passport_lock);

    pr_info("KPASS: added passport for pid=%d uid=%d\n", pid, uid);
    return 0;
}

int remove_passport_pid(int pid)
{
    struct passport_entry *entry;
    int found = 0;
    unsigned int hash = passport_hash(pid);

    spin_lock(&passport_lock);
    list_for_each_entry(entry, &passport_table[hash], list) {
        if (entry->pid == pid) {
            list_del(&entry->list);
            kfree(entry);
            found = 1;
            pr_info("KPASS: removed passport for pid=%d\n", pid);
            break;
        }
    }
    spin_unlock(&passport_lock);
    return found ? 0 : -ENOENT;
}

void clear_passport(void)
{
    struct passport_entry *entry, *tmp;
    int i;

    spin_lock(&passport_lock);
    for (i = 0; i < PASSPORT_HASH_SIZE; i++) {
        list_for_each_entry_safe(entry, tmp, &passport_table[i], list) {
            list_del(&entry->list);
            kfree(entry);
        }
    }
    spin_unlock(&passport_lock);
    pr_info("KPASS: cleared all passports\n");
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

void init_passport(void)
{
    int i;
    for (i = 0; i < PASSPORT_HASH_SIZE; i++)
        INIT_LIST_HEAD(&passport_table[i]);

    pr_info("KPASS: passport module initialized (hash table ready)\n");
}
