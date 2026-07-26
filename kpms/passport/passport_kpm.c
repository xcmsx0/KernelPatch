/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) KPatch Team
 */

#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <kputils.h>

KPM_NAME("kpm-passport");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KPatch Team");
KPM_DESCRIPTION("Kernel Passport KPM Module with Netlink");

/* ===== 白名单哈希表 ===== */
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

/* ===== 添加通行证 ===== */
static int add_passport_entry(int pid, uid_t uid)
{
    struct passport_entry *entry;
    unsigned int hash = passport_hash(pid);

    spin_lock(&passport_lock);
    list_for_each_entry(entry, &passport_table[hash], list) {
        if (entry->pid == pid && entry->uid == uid) {
            spin_unlock(&passport_lock);
            return 0; // 已存在
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

    logkd("KPASS_KPM: added pid %d uid %d\n", pid, uid);
    return 0;
}

/* ===== 检查函数（由 kpimg 调用） ===== */
static int check_passport(void)
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
        logkd("KPASS_KPM: pid %d uid %d PASS\n", pid, uid);
    else
        logkd("KPASS_KPM: pid %d uid %d DENIED\n", pid, uid);

    return found;
}

/* ===== Netlink 通信 ===== */
#define PASSPORT_NETLINK_UNIT 26
#define PASSPORT_MSG_ADD_PID  1

static struct sock *nl_sk = NULL;

static void netlink_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct {
        int pid;
        uid_t uid;
    } *payload;
    int pid;

    nlh = (struct nlmsghdr *)skb->data;
    if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(*payload)) {
        logkfd("KPASS_KPM: invalid message length\n");
        return;
    }

    payload = (typeof(payload))NLMSG_DATA(nlh);
    pid = payload->pid;

    if (nlh->nlmsg_type == PASSPORT_MSG_ADD_PID) {
        add_passport_entry(pid, payload->uid);
        logkd("KPASS_KPM: received ADD_PID: %d\n", pid);
    } else {
        logkfd("KPASS_KPM: unknown message type: %d\n", nlh->nlmsg_type);
    }
}

static int netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = netlink_recv,
    };

    nl_sk = netlink_kernel_create(&init_net, PASSPORT_NETLINK_UNIT, &cfg);
    if (!nl_sk) {
        logkfd("KPASS_KPM: netlink_kernel_create failed\n");
        return -ENOMEM;
    }
    logkd("KPASS_KPM: netlink socket created (unit %d)\n", PASSPORT_NETLINK_UNIT);
    return 0;
}

static void netlink_exit(void)
{
    if (nl_sk) {
        netlink_kernel_release(nl_sk);
        nl_sk = NULL;
        logkd("KPASS_KPM: netlink socket released\n");
    }
}

/* ===== 模块初始化（由 KPM 框架调用） ===== */
static long passport_init(const char *args, const char *event, void *__user reserved)
{
    int i;
    unsigned long check_addr;

    logkd("KPASS_KPM: loading passport KPM module\n");

    /* 初始化白名单 */
    for (i = 0; i < PASSPORT_HASH_SIZE; i++)
        INIT_LIST_HEAD(&passport_table[i]);

    /* 1. 设置 kpassport_check 钩子 */
    check_addr = kp_lookup_name("kpassport_check");
    if (!check_addr) {
        logkfd("KPASS_KPM: symbol kpassport_check not found!\n");
        return -ENOENT;
    }

    /* 保存原函数指针并替换 */
    int (*orig_check)(void) = *(int (**)(void))check_addr;
    *(int (**)(void))check_addr = check_passport;
    logkd("KPASS_KPM: hooked kpassport_check (orig=%p, new=%p)\n", orig_check, check_passport);

    /* 2. 初始化 Netlink */
    if (netlink_init() < 0) {
        *(int (**)(void))check_addr = orig_check;
        return -ENOMEM;
    }

    return 0;
}

static long passport_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("KPASS_KPM: control called, args: %s\n", args);
    return 0;
}

static long passport_exit(void *__user reserved)
{
    unsigned long check_addr;
    struct passport_entry *entry, *tmp;
    int i;

    logkd("KPASS_KPM: unloading passport KPM module\n");

    /* 1. 恢复钩子 */
    check_addr = kp_lookup_name("kpassport_check");
    if (check_addr) {
        *(int (**)(void))check_addr = NULL;
        logkd("KPASS_KPM: restored kpassport_check\n");
    }

    /* 2. 释放 Netlink */
    netlink_exit();

    /* 3. 清空白名单 */
    spin_lock(&passport_lock);
    for (i = 0; i < PASSPORT_HASH_SIZE; i++) {
        list_for_each_entry_safe(entry, tmp, &passport_table[i], list) {
            list_del(&entry->list);
            kfree(entry);
        }
    }
    spin_unlock(&passport_lock);

    logkd("KPASS_KPM: unloaded\n");
    return 0;
}

/* ===== KPM 框架宏 ===== */
KPM_INIT(passport_init);
KPM_CTL0(passport_control0);
KPM_EXIT(passport_exit);
static int netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = netlink_recv,
    };

    nl_sk = netlink_kernel_create(&init_net, PASSPORT_NETLINK_UNIT, &cfg);
    if (!nl_sk) {
        printk(KERN_ERR "KPASS_KPM: netlink_kernel_create failed\n");
        return -ENOMEM;
    }
    printk(KERN_INFO "KPASS_KPM: netlink socket created (unit %d)\n", PASSPORT_NETLINK_UNIT);
    return 0;
}

static void netlink_exit(void)
{
    if (nl_sk) {
        netlink_kernel_release(nl_sk);
        nl_sk = NULL;
        printk(KERN_INFO "KPASS_KPM: netlink socket released\n");
    }
}

/* ===== 钩子函数指针 ===== */
static int (*orig_check)(void) = NULL;

/* ===== 模块加载/卸载 ===== */
static int __init passport_kpm_init(void)
{
    int i;
    unsigned long check_addr;

    printk(KERN_INFO "KPASS_KPM: loading passport KPM module\n");

    /* 初始化白名单 */
    for (i = 0; i < PASSPORT_HASH_SIZE; i++)
        INIT_LIST_HEAD(&passport_table[i]);

    /* 1. 设置检查钩子 */
    check_addr = kp_lookup_name("kpassport_check");
    if (!check_addr) {
        printk(KERN_ERR "KPASS_KPM: symbol kpassport_check not found!\n");
        return -ENOENT;
    }
    orig_check = *(int (**)(void))check_addr;
    *(int (**)(void))check_addr = check_passport;
    printk(KERN_INFO "KPASS_KPM: hooked kpassport_check\n");

    /* 2. 初始化 Netlink */
    if (netlink_init() < 0) {
        /* 回滚钩子 */
        *(int (**)(void))check_addr = orig_check;
        return -ENOMEM;
    }

    return 0;
}

static void __exit passport_kpm_exit(void)
{
    unsigned long check_addr;
    struct passport_entry *entry, *tmp;
    int i;

    printk(KERN_INFO "KPASS_KPM: unloading passport KPM module\n");

    /* 1. 恢复钩子 */
    check_addr = kp_lookup_name("kpassport_check");
    if (check_addr) {
        *(int (**)(void))check_addr = orig_check;
        printk(KERN_INFO "KPASS_KPM: restored kpassport_check\n");
    }

    /* 2. 释放 Netlink */
    netlink_exit();

    /* 3. 清空白名单 */
    spin_lock(&passport_lock);
    for (i = 0; i < PASSPORT_HASH_SIZE; i++) {
        list_for_each_entry_safe(entry, tmp, &passport_table[i], list) {
            list_del(&entry->list);
            kfree(entry);
        }
    }
    spin_unlock(&passport_lock);

    printk(KERN_INFO "KPASS_KPM: unloaded\n");
}

module_init(passport_kpm_init);
module_exit(passport_kpm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KPatch Team");
MODULE_DESCRIPTION("Kernel Passport KPM Module with Netlink");
