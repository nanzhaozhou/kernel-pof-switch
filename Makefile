obj-m += pofswitch.o
pofswitch-y := ./common/pof_byte_transfer.o
pofswitch-y += ./common/pof_basefunc.o
pofswitch-y += ./datapath/pof_instruction.o
pofswitch-y += ./datapath/pof_action.o
pofswitch-y += ./datapath/pof_datapath.o
pofswitch-y += ./datapath/pof_lookup.o
pofswitch-y += ./local_resource/pof_group.o
pofswitch-y += ./local_resource/pof_counter.o
pofswitch-y += ./local_resource/pof_port.o
pofswitch-y += ./local_resource/pof_meter.o
pofswitch-y += ./local_resource/pof_flow_table.o
pofswitch-y += ./local_resource/pof_local_resource.o
pofswitch-y += ./kernel/pofswitch.o
pofswitch-y += ./kernel/pof_encap.o
pofswitch-y += ./kernel/pof_parse.o

flags-y := ./include

KBUILD_CFLAGS += -O0

all:
	#CONFIG_DEBUG_INFO=1 make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

install:
	cd userspace && make && cd ..
	cp ./userspace/pofswitch /usr/local/sbin
	cp pofswitch.ko /lib/modules/$(shell uname -r)/
	depmod /lib/modules/$(shell uname -r)/pofswitch.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
