#include <passport.h>
#include <linux/printk.h>

/* 函数指针，由 KPM 模块设置 */
int (*kpassport_check)(void) = NULL;
KP_EXPORT_SYMBOL(kpassport_check);

int has_passport(void)
{
    if (kpassport_check)
        return kpassport_check();
    /* 默认拒绝 */
    pr_debug("KPASS: no check function set, denying\n");
    return 0;
}

void init_passport(void)
{
    pr_info("KPASS: passport hook initialized, waiting for KPM module\n");
}
