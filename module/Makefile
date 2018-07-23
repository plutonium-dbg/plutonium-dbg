obj-m += plutonium-dbg.o

.PHONY: all debug clean

all:
	make -C ../setup/linux M=$(PWD) modules

debug:
	make CFLAGS_plutonium-dbg.o=-DMOD_DEBUG_ENABLE_TRACE -C ../setup/linux M=$(PWD) modules

clean:
	make -C ../setup/linux M=$(PWD) clean
