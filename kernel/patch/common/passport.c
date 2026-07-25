// kernel/patch/common/passport.c
#include <passport.h>
#include <linux/printk.h>

/* 核心检查函数：临时全部放行 */
int has_passport(struct task_struct *task)
{
    pr_info("KPASS: has_passport called\n");
    return 1;   // 对所有进程放行，用于验证补丁加载
}

/* 初始化函数 */
void init_passport(void)
{
    pr_info("KPASS: init_passport called, passport module loaded\n");
}

/* 空函数（占位） */
int remove_passport_pid(pid_t pid)
{
    return 0;
}

void clear_passport(void)
{
}
