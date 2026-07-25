#ifndef _KPASSPORT_H_
#define _KPASSPORT_H_

#include <linux/types.h>   // 提供 pid_t

void init_passport(void);
int has_passport(void);            // 不再传参，直接使用 current
int remove_passport_pid(pid_t pid);
void clear_passport(void);

#endif
