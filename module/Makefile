obj-m += plutonium-dbg.o

KERNEL=../setup/linux
#KERNEL=/lib/modules/$(shell uname -r)/build

.PHONY: all debug clean

all:
	make -C $(KERNEL) M=$(PWD) modules

debug:
	make CFLAGS_plutonium-dbg.o="-g -DMOD_DEBUG_ENABLE_TRACE" -C $(KERNEL) M=$(PWD) modules

mutexdebug:
	make CFLAGS_plutonium-dbg.o="-g -DMOD_DEBUG_ENABLE_TRACE -DMOD_DEBUG_ENABLE_MUTEX_TRACE" -C $(KERNEL) M=$(PWD) modules

clean:
	make -C $(KERNEL) M=$(PWD) clean
