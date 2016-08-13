#ifndef __POF_COMMON_H__
#define __POF_COMMON_H__

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

/* TRUE or FALSE. */
#define TRUE 1
#define FALSE 0

/* Max length of one message sent to controller */
#define POF_MESSAGE_LEN_MAX 1514

/* Define message size. */
#define POF_MESSAGE_SIZE (2560)

/* Define the byte order of the system. */
#define POF_LITTLE_ENDIAN (0)
#define POF_BIG_ENDIAN (1)
//#if (__BYTE_ORDER == __BIG_ENDIAN)
//#define POF_BYTE_ORDER POF_BIG_ENDIAN
//#else // __BYTE_ORDER
#define POF_BYTE_ORDER POF_LITTLE_ENDIAN
//#endif // __BYTE_ORDER

/* Initialize the Xid value. */
#define POF_INITIAL_XID (0)

/* Soft Switch performance after Controller disconnection. */
/* The Soft Switch will try to reconnect the Controller after Controller disconnection. */
#define POF_AFTER_CTRL_DISCONN_RECONN    (1)
/* The Soft Switch will be shut down after Controller disconnection. */
#define POF_AFTER_CTRL_DISCONN_SHUT_DOWN (2)
#define POF_PERFORM_AFTER_CTRL_DISCONN  POF_AFTER_CTRL_DISCONN_RECONN
//#define POF_PERFORM_AFTER_CTRL_DISCONN  POF_AFTER_CTRL_DISCONN_SHUT_DOWN

/* Check if the flow entry have already existed when add flow entry. */
//#define POF_ADD_ENTRY_CHECK_ON
//
/* Start datapath module. */
#define POF_DATAPATH_ON

/* Enable promisc mode. */
//#define POF_PROMISC_ON

/* Drop the packet which destination hwaddr is not local. */
//#define POF_RECVRAW_DHWADDR_LOCAL

/* Soft Switch performance when there is no flow entry matches the packet. */
/* The no match packet will be send upward to the Controller. */
#define POF_NOMATCH_PACKET_IN (1)
/* The no match packet will be drop. */
#define POF_NOMATCH_DROP      (2)
//#define POF_NOMATCH POF_NOMATCH_PACKET_IN
#define POF_NOMATCH POF_NOMATCH_DROP

/* Message queue structure. */
typedef struct pof_message_queue_t{
	struct list_head qhead;
	spinlock_t *splock;/* For concurrency. */
}pof_message_queue_t;

/* Message structure. */
typedef struct pof_message_t{
	char buf[POF_MESSAGE_LEN_MAX];
	uint32_t len;
	struct list_head list;
}pof_message_t;


/* Base function. */
extern uint32_t pofbf_message_queue_init(void);
extern uint32_t pofbf_message_queue_read(char *buf, uint32_t max_len);
extern uint32_t pofbf_message_queue_write(const char *message, uint32_t msg_len);





#endif
