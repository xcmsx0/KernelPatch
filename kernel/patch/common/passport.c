// kernel/patch/common/passport.c
#include <passport.h>
#include <linux/printk.h>
#include <linux/sched.h>

/* ===== 核心检查函数：临时全部放行 ===== */
int has_passport(struct task_struct *task)
{
    pr_info("KPASS: has_passport called for pid %d\n", task->pid);
    // 临时：对所有进程放行，用于验证补丁是否生效
    return 1;
}
EXPORT_SYMBOL(has_passport);

/* ===== 初始化（仅打印日志） ===== */
void init_passport(void)
{
    pr_info("KPASS: init_passport called, passport module loaded\n");
}
EXPORT_SYMBOL(init_passport);

/* ===== 空函数，保留供后续扩展 ===== */
int remove_passport_pid(pid_t pid)
{
    return 0;
}
EXPORT_SYMBOL(remove_passport_pid);

void clear_passport(void)
{
}
EXPORT_SYMBOL(clear_passport);
