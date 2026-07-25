# kpms/passport/Makefile
# 独立 KPM 模块 Makefile，不依赖上级目录的 Makefile.kpm

# 工具链（由 CI 传递 TARGET_COMPILE 环境变量）
CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

# 编译标志
CFLAGS = -Wall -fno-builtin -std=gnu11 -nostdinc -mgeneral-regs-only -O2
INCLUDE = -I../../kernel/include -I../../kernel/patch/include
LDFLAGS = -nostdlib -static -no-pie -T../../kpms/kpms.lds

# 目标文件
TARGET = passport.kpm
OBJS = passport_kpm.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

clean:
	rm -f *.o *.kpm
