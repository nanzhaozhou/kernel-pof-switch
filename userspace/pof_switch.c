#include <stdio.h>
#include "../include/pof_config.h"


/***********************************************************************
 * Main entry of the userspace control tool.
 * Form:     int main(int argc, char *argv[])
 * Input:    number of arg, args
 * Output:   NONE
 * Return:   NONE
 * Discribe: This function start the userspace control tool.
 ***********************************************************************/
int main(int argc, char *argv[]){

	uint32_t ret = RET_OK;

	/* Check whether the euid is root id. If not, QUIT. */
	ret = pof_check_root();
	if(RET_OK != ret){
		exit(0);
	}

    /* Get the config of the Soft Switch.  
	 * If it do return, it always return RET_OK.
	 * Otherwisw, we will directly quit.
	 */
    ret = pof_get_config(argc, argv);

	if(pof_close_demand()){
		/* Remove the kernel module. */
		printf("pof_close_demand\n");
		pof_rmmod();
		exit(0);
	}
	/* Install the kernel module, pass config into kernel space. */
	printf("pof_close_demand NONONO\n");
	pof_modprobe();
}

