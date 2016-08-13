#ifndef _POF_CONNECTION_H_
#define _POF_CONNECTION_H_


#include <linux/net.h> /* For struct socket */
#include <linux/types.h>

#include "pof_global.h"
#include "pof_common.h"/* For POF_MESSAGE_SIZE */

/* Define the string length of IPv4 address. */
#define POF_IP_ADDRESS_STRING_LEN (20)

/* Define echo interval .*/
#define POF_ECHO_INTERVAL (10)  /* Unit is second. */

/* Define the server's port number. */
#define POF_CONTROLLER_PORT_NUM (6633)

/* Define the max retry time of cnnection. */
#define POF_CONNECTION_MAX_RETRY_TIME (0XFFFFFFFF)

/* Define the retry interval of connection if connection fails. */
#define POF_CONNECTION_RETRY_INTERVAL (2)  /* Seconds. */

/* Define max size of sending buffer. */
#define POF_SEND_BUF_MAX_SIZE (POF_MESSAGE_SIZE)

/* Define max size of receiving buffer. */
#define POF_RECV_BUF_MAX_SIZE (POF_MESSAGE_SIZE)

/* Message queue attributes. */
#define POF_QUEUE_MESSAGE_LEN (POF_MESSAGE_SIZE)


/* Openflow device connection description. */
typedef struct pofsc_dev_conn_desc{
    /* Controller information. */
    char controller_ip[POF_IP_ADDRESS_STRING_LEN];  /* Ipv4 address of openflow controller. */
    uint16_t controller_port;

    /* Connection sock and socket buffers. */
    struct socket *sock; /* Socket pointer. */
    char send_buf[POF_SEND_BUF_MAX_SIZE];
    char recv_buf[POF_RECV_BUF_MAX_SIZE];
    char msg_buf[POF_QUEUE_MESSAGE_LEN];

    /* Connection retry count and connection state. */
    uint32_t conn_retry_interval; /* Unit is second. */
    uint32_t conn_retry_max;
    uint32_t conn_retry_count;
	/* Defined in pof_global.h-->. */
    pof_connect_status conn_status;

    /* Last echo reply time. */
    time_t last_echo_time;
}  pofsc_dev_conn_desc;


/* Define Soft Switch control module state. */
typedef enum{
    POFCS_CHANNEL_INVALID       = 0,
    POFCS_CHANNEL_CONNECTING    = 1,
    POFCS_CHANNEL_CONNECTED     = 2,
    POFCS_HELLO                 = 3,
    POFCS_REQUEST_FEATURE       = 4,
    POFCS_SET_CONFIG            = 5,
    POFCS_REQUEST_GET_CONFIG    = 6,
    POFCS_CHANNEL_RUN           = 7,
    POFCS_STATE_MAX             = 8,
} pof_channel_state;




/* Description of device connection. */
extern volatile pofsc_dev_conn_desc pofsc_conn_desc;

uint32_t pofec_set_error(uint16_t type, char *type_str, uint16_t code, char *error_str);



/* parse and encap. */
extern uint32_t pofec_reply_msg(uint8_t  type, \
                                uint32_t xid, \
                                uint32_t msg_len, \
                                uint8_t  *msg_body);

extern uint32_t pof_parse_msg_from_controller(char* msg_ptr);
extern uint32_t pofec_reply_error(uint16_t type, uint16_t code, char *s, uint32_t xid);





#endif // _POF_CONNECTION_H_
