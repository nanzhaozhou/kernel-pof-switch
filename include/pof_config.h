#ifndef __POF_CONFIG_H__
#define __POF_CONFIG_H__

#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <endian.h>

/* TRUE or FALSE. */
#define TRUE 1
#define FALSE 0

/* Define return value. */
#define RET_OK 0
#define RET_ERROR 1

/* Version. */
#define POFSWITCH_VERSION "POFSwitch-1.3.4-kernel"

/* Max length of configure string value. */
#define POF_STRING_MAX_LEN (100)

/* Max length of modprobe command. */
#define POF_MODPROBE_MAX_LEN (1000)

/* Define the string length of IPv4 address. */
#define POF_IP_ADDRESS_STRING_LEN (20)

/* Define the server's port number. */
#define POF_CONTROLLER_PORT_NUM (6633)

#define POF_CONN_CONFIG_COMMAND
#define POF_CONN_CONFIG_FILE

/* Define the byte order of the system. */
#define POF_LITTLE_ENDIAN (0)
#define POF_BIG_ENDIAN (1)
#if (__BYTE_ORDER == __LITTLE_ENDIAN)
#define POF_BYTE_ORDER POF_LITTLE_ENDIAN
#else // __BYTE_ORDER
#define POF_BYTE_ORDER POF_BIG_ENDIAN
#endif // __BYTE_ORDER

/* Start datapath module. */
#define POF_DATAPATH_ON

/* Modprobe parameter name length. */
#define POF_MODP_PARA_LEN 11

#define POF_STRING_PAIR_MAX_LEN (64)
struct pof_str_pair{
    char item[POF_STRING_PAIR_MAX_LEN];
    char cont[POF_STRING_PAIR_MAX_LEN];
};

/* Stores parameters passed to kernel. */
struct pof_config {
    struct pof_str_pair ctrl_ip;
    struct pof_str_pair conn_port;
    struct pof_str_pair mm_table_number;
    struct pof_str_pair lpm_table_number;
    struct pof_str_pair em_table_number;
    struct pof_str_pair dt_table_number;
    struct pof_str_pair flow_table_size;
    struct pof_str_pair flow_table_key_length;
    struct pof_str_pair meter_number;
    struct pof_str_pair counter_number;
    struct pof_str_pair group_number;
    struct pof_str_pair device_port_number_max;
};

/* Used by main function. */
extern uint32_t pof_check_root();
extern uint32_t pof_get_config(int argc, char *argv[]);
extern uint32_t pof_close_demand();
extern void pof_rmmod();
extern void pof_modprobe();


#endif //__POF_CONFIG_H__
