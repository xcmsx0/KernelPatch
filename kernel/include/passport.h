#ifndef _KPASSPORT_H_
#define _KPASSPORT_H_

void init_passport(void);
int has_passport(void);          // 改为无参，直接使用 current
int remove_passport_pid(pid_t pid);
void clear_passport(void);

#endif
