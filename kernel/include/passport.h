// kernel/include/passport.h
#ifndef _KPASSPORT_H_
#define _KPASSPORT_H_

#include <linux/types.h>
#include <linux/sched.h>

/* 初始化通行证子系统（在 su_compat_init 中调用） */
void init_passport(void);

/* 检查当前进程是否有通行证 */
int has_passport(struct task_struct *task);

/* 添加 PID 到通行证列表（供 proc 写回调调用） */
int add_passport_pid(pid_t pid);

/* 移除 PID（可选） */
int remove_passport_pid(pid_t pid);

/* 清空所有通行证（可选） */
void clear_passport(void);

#endif