#include <stdio.h>  /* For printf sprintf. */
#include <unistd.h> /* For geteuid. */
#include <string.h> /* For strncpy. */
#include <stdint.h> /* For uint32_t. */
#include <getopt.h> /* For getopt_long. */

#include "../include/pof_config.h"

/* Store configs passed to kernel. */
static struct pof_config g_configs;

/* User defined config file name. */
static char pofc_cmd_input_file_name[POF_STRING_MAX_LEN] = "\0";

/* Controller ip. */
static char pof_controller_ip_addr[POF_IP_ADDRESS_STRING_LEN] = "192.168.1.1";

/* Controller port. */
static uint16_t pof_controller_port = POF_CONTROLLER_PORT_NUM;

/* Parameters configured by user commands will not be configured by file again. */
uint32_t pofc_cmd_set_ip_ret = FALSE;
uint32_t pofc_cmd_set_port_ret = FALSE;
uint32_t pofc_cmd_set_config_file = FALSE;
uint32_t pofc_cmd_set_close = FALSE;

/* Modprobe parameter name string. */
static char *modprb_para_str[POF_MODP_PARA_LEN] = {
	" conn_port=", " mm_table_number=",
	" lpm_table_number=", " em_table_number=",
	" dt_table_number=", " flow_table_size=",
	" flow_table_key_length=", " meter_number=",
	" counter_number=", " group_number=",
	" device_port_number_max="
};



#ifdef POF_CONN_CONFIG_COMMAND

#define COMMAND_STR_LEN (30)
#define HELP_STR_LEN    (50)

//  CONFIG_CMD(OPT,OPTSTR,LONG,FUNC,HELP)
#define CONFIG_CMDS \
    CONFIG_CMD('i',"i:","ip-addr",ip_addr,"IP address of the Controller. Default is 192.168.1.1.")                      \
    CONFIG_CMD('p',"p:","port",port,"Connection port number. Default is 6633.")              \
    CONFIG_CMD('f',"f:","file",file,"Set config file.")                                      \
    CONFIG_CMD('t',"t","test",test,"Test.")                     \
    CONFIG_CMD('h',"h","help",help,"Print help message.")                                    \
    CONFIG_CMD('c',"c","close",close,"Close the POFSwitch.")                                    \
    CONFIG_CMD('v',"v","version",version,"Print the version number of POFSwitch.")

/* Local functions. */
static void pof_set_init_configs();
static uint32_t pof_set_init_config_by_command(int argc, char *argv[]);
static uint32_t pof_set_init_config_by_file();
static uint32_t pof_set_controller_ip(char *ip_str);
static uint32_t pof_set_controller_port(uint16_t port);
static uint32_t pof_set_MM_table_number(uint16_t num);
static uint32_t pof_set_LPM_table_number(uint16_t num);
static uint32_t pof_set_EM_table_number(uint16_t num);
static uint32_t pof_set_DT_table_number(uint16_t num);
static uint32_t pof_set_FLOW_table_size(uint16_t num);
static uint32_t pof_set_FLOW_table_key_length(uint16_t num);
static uint32_t pof_set_METER_number(uint16_t num);
static uint32_t pof_set_COUNTER_number(uint16_t num);
static uint32_t pof_set_GROUP_number(uint16_t num);
static uint32_t pof_set_DEVICE_port_number_max(uint16_t num);



static uint32_t
start_cmd_ip_addr(char *optarg)
{
	if(!optarg){
		printf("--ip_addr, option value is NULL, correct format: -i [option_value]\n");
		exit(0);
	}
    pof_set_controller_ip(optarg);
    pofc_cmd_set_ip_ret = TRUE;
}

static uint32_t
start_cmd_port(char *optarg)
{
	if(!optarg){
		printf("--port, option value is NULL, correct format: -p [option_value]\n");
		exit(0);
	}
    pof_set_controller_port(atoi(optarg));
    pofc_cmd_set_port_ret = TRUE;
}

static uint32_t
start_cmd_file(char *optarg)
{
	if(!optarg){
		printf("--file, option value is NULL, correct format: -f [option_value]\n");
		exit(0);
	}
    strncpy(pofc_cmd_input_file_name, optarg, POF_STRING_MAX_LEN-1);
    pofc_cmd_set_config_file = TRUE;
}

static uint32_t
start_cmd_test(char *optarg)
{
    exit(0);
}

static uint32_t
start_cmd_help(char *optarg)
{
	printf("Usage: pofswitch [options] [target] ...\n");
	printf("Options:\n");

#define CONFIG_CMD(OPT,OPTSTR,LONG,FUNC,HELP) \
    printf("  -%c, --%-24s%-50s\n",OPT,LONG,HELP);
    CONFIG_CMDS
#undef CONFIG_CMD

	printf("\nReport bugs to <lianglsh@mail.ustc.edu.com>\n");
    exit(0);
}

static uint32_t
start_cmd_close(char *optarg)
{
    printf("Going to close the POFSWitch!\n");
	pofc_cmd_set_close = TRUE;
}

static uint32_t
start_cmd_version(char *optarg)
{
    printf("Version: %s\n", POFSWITCH_VERSION);
    exit(0);
}


/***********************************************************************
 * Initialize the config by command.
 * Form:     static uint32_t pof_set_init_config_by_command(int argc, char *argv[])
 * Input:    command arg numbers, command args.
 * Output:   NONE
 * Return:   RET_OK or ERROR code
 * Discribe: This function initialize the config of Soft Switch by user's 
 *           command arguments. 
 *           -i: set the IP address of the Controller.
 *           -p: set the port to connect to the Controller.
 ***********************************************************************/
static uint32_t pof_set_init_config_by_command(int argc, char *argv[]){
	uint32_t ret = RET_OK;
#define OPTSTRING_LEN (50)
	char optstring[OPTSTRING_LEN];
#undef OPTSTRING_LEN
 	struct option long_options[] = {
#define CONFIG_CMD(OPT,OPTSTR,LONG,FUNC,HELP) {LONG,0,NULL,OPT},
        CONFIG_CMDS
#undef CONFIG_CMD
		{NULL,0,NULL,0}
	};
	int ch;

#define CONFIG_CMD(OPT,OPTSTR,LONG,FUNC,HELP) strncat(optstring,OPTSTR,COMMAND_STR_LEN);
    CONFIG_CMDS
#undef CONFIG_CMD

	while((ch=getopt_long(argc, argv, optstring, long_options, NULL)) != -1){
		switch(ch){
			case '?':
				exit(0);
				break;
#define CONFIG_CMD(OPT,OPTSTR,LONG,FUNC,HELP)   \
            case OPT:                           \
                start_cmd_##FUNC(optarg);       \
                break;

            CONFIG_CMDS
#undef CONFIG_CMD
			default:
				break;
		}
	}
}

/* Whether user demand to quit the switch. */
uint32_t pof_close_demand(){
	return pofc_cmd_set_close;
}

#endif // POF_CONN_CONFIG_COMMAND

#ifdef POF_CONN_CONFIG_FILE

enum pof_init_config_type{
	POFICT_CONTROLLER_IP	= 0,
	POFICT_CONNECTION_PORT  = 1,
	POFICT_MM_TABLE_NUMBER = 2,
	POFICT_LPM_TABLE_NUMBER = 3,
	POFICT_EM_TABLE_NUMBER  = 4,
	POFICT_DT_TABLE_NUMBER  = 5,
	POFICT_FLOW_TABLE_SIZE  = 6,
	POFICT_FLOW_TABLE_KEY_LENGTH = 7,
	POFICT_METER_NUMBER     = 8,
	POFICT_COUNTER_NUMBER   = 9,
	POFICT_GROUP_NUMBER     = 10,
	POFICT_DEVICE_PORT_NUMBER_MAX = 11,

	POFICT_CONFIG_TYPE_MAX,
};

static char *config_type_str[POFICT_CONFIG_TYPE_MAX] = {
	"Controller_IP", "Connection_port", 
	"MM_table_number", "LPM_table_number", "EM_table_number", "DT_table_number",
	"Flow_table_size", "Flow_table_key_length", 
	"Meter_number", "Counter_number", "Group_number", 
	"Device_port_number_max"
};

static uint8_t pofsic_get_config_type(char *str){
	uint8_t i;

	for(i=0; i<POFICT_CONFIG_TYPE_MAX; i++){
		if(strcmp(str, config_type_str[i]) == 0){
			return i;
		}
	}

	return 0xff;
}

static uint32_t pofsic_get_config_data(FILE *fp, uint32_t *ret_p){
	char str[POF_STRING_MAX_LEN];

	if(fscanf(fp, "%s", str) != 1){
		*ret_p = RET_ERROR;
		return RET_ERROR;
	}else{
		return atoi(str);
	}
}

/***********************************************************************
 * Initialize the config by file.
 * Form:     static uint32_t pof_set_init_config_by_file()
 * Input:    NONE
 * Output:   NONE
 * Return:   RET_OK or [Just exit]
 * Discribe: This function initialize the config of Soft Switch by "config"
 *           file. The config's content:
 *			 "Controller_IP", "Connection_port", 
 *			 "MM_table_number", "LPM_table_number", "EM_table_number", "DT_table_number",
 *			 "Flow_table_size", "Flow_table_key_length", 
 *			 "Meter_number", "Counter_number", "Group_number", 
 *			 "Device_port_number_max"
 ***********************************************************************/
static uint32_t pof_set_init_config_by_file(){
	uint32_t ret = RET_OK, data = 0;
	char     filename_relative[] = "./pofswitch_config.conf";
	char     filename_absolute[] = "/etc/pofswitch/pofswitch_config.conf";
	char     filename_final[POF_STRING_MAX_LEN] = "\0";
	char     str[POF_STRING_MAX_LEN] = "\0";
	char     ip_str[POF_STRING_MAX_LEN] = "\0";
	FILE     *fp = NULL;
	uint8_t  config_type = 0;

	if((fp = fopen(pofc_cmd_input_file_name, "r")) == NULL){
		if(pofc_cmd_set_config_file != FALSE){
			printf("The file %s is not exist.\n", pofc_cmd_input_file_name);
		}
		if((fp = fopen(filename_relative, "r")) == NULL){
			printf("The file %s is not exist.\n", filename_relative);
			if((fp = fopen(filename_absolute, "r")) == NULL){
				printf("The file %s is not exist.\n", filename_absolute);
				exit(0);
			}else{
				strncpy(filename_final, filename_absolute, POF_STRING_MAX_LEN-1);
			}
		}else{
			strncpy(filename_final, filename_relative, POF_STRING_MAX_LEN-1);
		}
	}else{
        strncpy(filename_final, pofc_cmd_input_file_name, POF_STRING_MAX_LEN-1);
	}

    printf("The config file %s have been loaded.\n", filename_final);
	
	while(fscanf(fp, "%s", str) == 1){
		config_type = pofsic_get_config_type(str);
		if(config_type == POFICT_CONTROLLER_IP){
			if(fscanf(fp, "%s", ip_str) != 1){
				ret = RET_ERROR;
				break;
			}else{
				if(pofc_cmd_set_ip_ret == FALSE){
					pof_set_controller_ip(ip_str);
				}
			}
		}else{
			data = pofsic_get_config_data(fp, &ret);
			switch(config_type){
				case POFICT_CONNECTION_PORT:
					if(pofc_cmd_set_port_ret == FALSE){
	                    pof_set_controller_port(data);
					}
					break;
				case POFICT_MM_TABLE_NUMBER:
					pof_set_MM_table_number(data);
					break;
				case POFICT_LPM_TABLE_NUMBER:
					pof_set_LPM_table_number(data);
					break;
				case POFICT_EM_TABLE_NUMBER:
					pof_set_EM_table_number(data);
					break;
				case POFICT_DT_TABLE_NUMBER:
					pof_set_DT_table_number(data);
					break;
				case POFICT_FLOW_TABLE_SIZE:
					pof_set_FLOW_table_size(data);
					break;
				case POFICT_FLOW_TABLE_KEY_LENGTH:
					pof_set_FLOW_table_key_length(data);
					break;
				case POFICT_METER_NUMBER:
					pof_set_METER_number(data);
					break;
				case POFICT_COUNTER_NUMBER:
					pof_set_COUNTER_number(data);
					break;
				case POFICT_GROUP_NUMBER:
					pof_set_GROUP_number(data);
					break;
				case POFICT_DEVICE_PORT_NUMBER_MAX:
					pof_set_DEVICE_port_number_max(data);
					break;
				default:
					ret = RET_ERROR;
					break;
			}
		}

		if(ret != RET_OK){
			printf("Can't load config file: Wrong config format.\n");
			fclose(fp);
			exit(0);
		}
	}

	fclose(fp);
	return ret;
}
#endif // POF_CONN_CONFIG_FILE


/***********************************************************************
 * Check whether the euid is the root id.
 * Form:     uint32_t pof_check_root()
 * Input:    NONE
 * Output:   NONE
 * Return:   RET_OK or ERROR code
 * Discribe: This function Check whether the euid is the root id.
 *			 If not, we will exit in the upper main function.
 ***********************************************************************/
uint32_t pof_check_root(){
	/* Root id = 0. */
	if(geteuid() == 0){
		return RET_OK;
	}else{
		printf("pofswitch ERROR: Permission denied.\n");
		return RET_ERROR;
	}
}

/***********************************************************************
 * Get the config by file or command.
 * Form:     uint32_t pof_get_config(int argc, char *argv[])
 * Input:    number of arg, args
 * Output:   NONE
 * Return:   RET_OK
 * Discribe: This function gets the config of Soft Switch by "config"
 *           file or command arguments.
 ***********************************************************************/
uint32_t pof_get_config(int argc, char *argv[]){
	uint32_t ret = RET_OK;
    pof_set_init_configs();

#ifdef POF_CONN_CONFIG_COMMAND
	ret = pof_set_init_config_by_command(argc, argv);
#endif
#ifdef POF_CONN_CONFIG_FILE
	ret = pof_set_init_config_by_file();
#endif 
    
	return RET_OK;
}


/***********************************************************************
 * Init the configure parameters.
 * Form:     uint32_t pof_set_init_config()
 * Input:    NONE
 * Output:   NONE
 * Return:   RET_OK 
 * Discribe: This function inits the config parameters. 
 ***********************************************************************/
static void pof_set_init_configs(){
    strncpy(g_configs.ctrl_ip.item, "CONTROLLER IP", POF_STRING_PAIR_MAX_LEN-1);
    strncpy(g_configs.ctrl_ip.cont, pof_controller_ip_addr, POF_STRING_PAIR_MAX_LEN-1);

    strncpy(g_configs.conn_port.item, "CONNECTION PORT", POF_STRING_PAIR_MAX_LEN-1);
    sprintf(g_configs.conn_port.cont, "%u", pof_controller_port);

    strncpy(g_configs.mm_table_number.item, "MM_TABLE_NUMBER", POF_STRING_PAIR_MAX_LEN-1);
    strncpy(g_configs.mm_table_number.cont, "10", POF_STRING_PAIR_MAX_LEN-1);

    strncpy(g_configs.lpm_table_number.item, "LPM_TABLE_NUMBER", POF_STRING_PAIR_MAX_LEN-1);
    strncpy(g_configs.lpm_table_number.cont, "10", POF_STRING_PAIR_MAX_LEN-1);

    strncpy(g_configs.em_table_number.item, "EM_TABLE_NUMBER", POF_STRING_PAIR_MAX_LEN-1);
    strncpy(g_configs.em_table_number.cont, "5", POF_STRING_PAIR_MAX_LEN-1);

    strncpy(g_configs.dt_table_number.item, "DT_TABLE_NUMBER", POF_STRING_PAIR_MAX_LEN-1);
    strncpy(g_configs.dt_table_number.cont, "20", POF_STRING_PAIR_MAX_LEN-1);

    strncpy(g_configs.flow_table_size.item, "FLOW_TABLE_SIZE", POF_STRING_PAIR_MAX_LEN-1);
    strncpy(g_configs.flow_table_size.cont, "6000", POF_STRING_PAIR_MAX_LEN-1);

    strncpy(g_configs.flow_table_key_length.item, "FLOW_TABLE_KEY_LENGTH", POF_STRING_PAIR_MAX_LEN-1);
    strncpy(g_configs.flow_table_key_length.cont, "320", POF_STRING_PAIR_MAX_LEN-1);

    strncpy(g_configs.meter_number.item, "METER_NUMBER", POF_STRING_PAIR_MAX_LEN-1);
    strncpy(g_configs.meter_number.cont, "1024", POF_STRING_PAIR_MAX_LEN-1);

    strncpy(g_configs.counter_number.item, "COUNTER_NUMBER", POF_STRING_PAIR_MAX_LEN-1);
    strncpy(g_configs.counter_number.cont, "512", POF_STRING_PAIR_MAX_LEN-1);

    strncpy(g_configs.group_number.item, "GROUP_NUMBER", POF_STRING_PAIR_MAX_LEN-1);
    strncpy(g_configs.group_number.cont, "1024", POF_STRING_PAIR_MAX_LEN-1);

    strncpy(g_configs.device_port_number_max.item, "DEVICE_PORT_NUMBER_MAX", POF_STRING_PAIR_MAX_LEN-1);
    strncpy(g_configs.device_port_number_max.cont, "20", POF_STRING_PAIR_MAX_LEN-1);

}


/* Set the Controller's IP address. */
static uint32_t pof_set_controller_ip(char *ip_str){
	strncpy(pof_controller_ip_addr, ip_str, POF_IP_ADDRESS_STRING_LEN);
	strncpy(g_configs.ctrl_ip.cont, ip_str, POF_IP_ADDRESS_STRING_LEN);
	return RET_OK;
}

/* Set the Controller's port. */
uint32_t pof_set_controller_port(uint16_t port){
	pof_controller_port = port;
    sprintf(g_configs.conn_port.cont, "%u", port);
	return RET_OK;
}

/* Set the mm_table_number. */
uint32_t pof_set_MM_table_number(uint16_t num){
    sprintf(g_configs.mm_table_number.cont, "%u", num);
	return RET_OK;
}

/* Set the lpm_table_number. */
uint32_t pof_set_LPM_table_number(uint16_t num){
    sprintf(g_configs.lpm_table_number.cont, "%u", num);
	return RET_OK;
}

/* Set the em_table_number. */
uint32_t pof_set_EM_table_number(uint16_t num){
    sprintf(g_configs.em_table_number.cont, "%u", num);
	return RET_OK;
}

/* Set the dt_table_number. */
uint32_t pof_set_DT_table_number(uint16_t num){
    sprintf(g_configs.dt_table_number.cont, "%u", num);
	return RET_OK;
}

/* Set the flow_table_size. */
uint32_t pof_set_FLOW_table_size(uint16_t num){
    sprintf(g_configs.flow_table_size.cont, "%u", num);
	return RET_OK;
}

/* Set the flow_table_key_length. */
uint32_t pof_set_FLOW_table_key_length(uint16_t num){
    sprintf(g_configs.flow_table_key_length.cont, "%u", num);
	return RET_OK;
}

/* Set the meter_number. */
uint32_t pof_set_METER_number(uint16_t num){
    sprintf(g_configs.meter_number.cont, "%u", num);
	return RET_OK;
}

/* Set the counter_number. */
uint32_t pof_set_COUNTER_number(uint16_t num){
    sprintf(g_configs.counter_number.cont, "%u", num);
	return RET_OK;
}

/* Set the group_number. */
uint32_t pof_set_GROUP_number(uint16_t num){
    sprintf(g_configs.group_number.cont, "%u", num);
	return RET_OK;
}

/* Set the device_port_number_max. */
uint32_t pof_set_DEVICE_port_number_max(uint16_t num){
    sprintf(g_configs.device_port_number_max.cont, "%u", num);
	return RET_OK;
}

/* Close the pofswitch. */
void pof_rmmod(){
	int ret = system("modprobe -r pofswitch");
	if(ret){
		printf("ERROR:can't rmmod pofswitch\n");
	}
}

/* Install the pofswitch, pass the config to kernel space. */
void pof_modprobe(){
	int i, pos = 0;
	char modprb[100] = "modprobe pofswitch ctrl_ip=\"";
	char cmd[POF_MODPROBE_MAX_LEN];

	/* 1 */
	strncpy(cmd + pos, modprb, strlen(modprb));
	pos += strlen(modprb);

	/* 2 */
	strncpy(cmd + pos, g_configs.ctrl_ip.cont, strlen(g_configs.ctrl_ip.cont));
	pos += strlen(g_configs.ctrl_ip.cont);
	*(cmd + pos) = '"';
	pos += 1;

	/* 3 */
	for(i=0; i < POF_MODP_PARA_LEN; i++){
		char *tmp = modprb_para_str[i];
		char *cont = (uint8_t *)&g_configs + (i + 1) * sizeof(struct pof_str_pair ) + POF_STRING_PAIR_MAX_LEN;
		strncpy(cmd + pos, tmp, strlen(tmp));
		pos += strlen(tmp);
		strncpy(cmd + pos, cont, strlen(cont));
		pos += strlen(cont);
	}

	*(cmd + pos) = '\0';
	printf("pof_modprobe, cmd=%s\n", cmd);
	int ret = system((const char *)cmd);
	if(ret){
		printf("ERROR:can't insmod pofswitch\n");
		exit(0);
	}
	printf("pofswitch launched successfully!\n");
}

