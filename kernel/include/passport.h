// kernel/include/passport.h
#ifndef _KPASSPORT_H_
#define _KPASSPORT_H_

#include <linux/sched.h>   // 提供 struct task_struct

void init_passport(void);
int has_passport(struct task_struct *task);
int remove_passport_pid(pid_t pid);
void clear_passport(void);

#endif
