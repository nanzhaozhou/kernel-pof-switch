#ifndef _POF_DATAPATH_H_
#define _POF_DATAPATH_H_

#include <linux/types.h>

#include "../include/pof_global.h"
#include "../include/pof_connection.h"
#include "../include/pof_byte_transfer.h"
#include "../include/pof_local_resource.h"
#include "../include/pof_datapath.h"
#include "../include/pof_log_print.h"


/* Max length of the raw packet received by local physical port. */
#define POFDP_PACKET_RAW_MAX_LEN (2048)

/* First table ID. */
#define POFDP_FIRST_TABLE_ID (0)

/* Max length of the metadata. */
#define POFDP_METADATA_MAX_LEN (128)

#define POFDP_ARG	struct pofdp_packet *dpp

/* Define the metadata field id. */
#define POFDP_METADATA_FIELD_ID (0xFFFF)

/* Define bit number in a byte. */
#define POF_BITNUM_IN_BYTE                  (8)

/* Left shift. */
#define POF_MOVE_BIT_LEFT(x,n)              ((x) << (n))

/* Right shift. */
#define POF_MOVE_BIT_RIGHT(x,n)             ((x) >> (n))

/* Transfer the length from bit unit to byte unit. Take the ceil. */
#define POF_BITNUM_TO_BYTENUM_CEIL(len_b)   ((uint32_t)(((len_b)+7) / POF_BITNUM_IN_BYTE ))

/* Packet infomation including data, length, received port. */
struct pofdp_packet{
    /* Input information. */
    uint32_t ori_port_id;       /* The original packet input port index. */
    uint32_t ori_len;           /* The original packet length.
                                 * If packet length has been changed, such as
                                 * in add field action, the ori_len will NOT
                                 * change. The len in metadata will update
                                 * immediatley in this situation. */
    uint8_t *buf;               /* The memery which stores the whole packet. */

    /* Output. */
    uint32_t output_port_id;    /* The output port index.*/
	uint16_t output_packet_len;			/* Byte unit. */
								/* The length of output packet. */
    uint16_t output_packet_offset;		/* Byte unit.*/
								/* The start position of output. */
	uint16_t output_metadata_len;		/* Byte unit. */
	uint16_t output_metadata_offset;	/* Bit unit. */
								/* The output metadata length and offset. 
								 * Packet data output right behind the metadata. */
	uint16_t output_whole_len;  /* = output_packet_len + output_metadata_len. */
	uint8_t *buf_out;			/* The memery which store the output data. */

    /* Offset. */
    uint16_t offset;					/* Byte unit. */
								/* The base offset of table field and actions. */
    uint8_t *buf_offset;        /* The packet pointer shift offset. 
                                 * buf_offset = buf + offset */
    uint32_t left_len;          /* Length of left packet after shifting offset. 
                                 * left_len = metadata->len - offset. */

    /* Metadata. */
    struct pofdp_metadata *metadata;
                                /* The memery which stores the packet metadata. 
								 * The packet WHOLE length and input port index 
								 * has been stored in metadata. */
    uint16_t metadata_len;      /* The length of packet metadata in byte. */

    /* Flow. */
    uint8_t table_type;         /* Type of table which contains the packet now. */
    uint8_t table_id;           /* Index of table which contains the packet now. */
    pof_flow_entry *flow_entry; /* The flow entry which match the packet. */

    /* Instruction & Actions. */
    struct pof_instruction *ins;/* The memery which stores the instructions need
                                 * to be implemented. */
    uint8_t ins_todo_num;       /* Number of instructions need to be implemented. */
	uint8_t ins_done_num;       /* Number of instructions have been done.*/
    struct pof_action *act;     /* Memery which stores the actions need to be
                                 * implemented. */
    uint8_t act_num;            /* Number of actions need to be implemented. */
    uint8_t packet_done;        /* Indicate whether the packet processing is
                                 * already done. 1 means done, 0 means not. */

	/* Meter. */
	uint16_t rate;				/* Rate. 0 means no limitation. */
};

/* Define Metadata structure. */
struct pofdp_metadata{
    uint16_t len;
    uint8_t port_id;
    uint8_t reserve;
    uint8_t data[]; 
};

/* Define datapath struction. */
struct pof_datapath{
    /* NONE promisc packet filter function. */
    uint32_t (*no_promisc)(unsigned char *mac_header_ptr, pof_port *port_ptr, uint8_t pkt_type);

    /* Promisc packet filter function. */
    uint32_t (*promisc)(unsigned char *mac_header_ptr, pof_port *port_ptr, uint8_t pkt_type);

    /* Set RAW packet filter function. */
    uint32_t (*filter)(unsigned char *mac_header_ptr, pof_port *port_ptr, uint8_t pkt_type);
};



extern uint32_t pof_datapath_init(void);
extern uint32_t pof_datapath_destroy(void);
extern void pofdp_cover_bit(uint8_t *data_ori, uint8_t *value, uint16_t pos_b, uint16_t len_b);
extern void pofdp_copy_bit(uint8_t *data_ori, uint8_t *data_res, uint16_t offset_b, uint16_t len_b);
extern uint32_t pofdp_get_32value(uint32_t *value, uint8_t type, void *u_, const struct pofdp_packet *dpp);
extern uint32_t pofdp_lookup_in_table(uint8_t **key_ptr, \
                                      uint8_t match_field_num, \
                                      poflr_flow_table table_vhal, \
                                      pof_flow_entry **entry_ptrptr);
extern uint32_t pofdp_action_execute(POFDP_ARG);
extern uint32_t pofdp_send_packet_in_to_controller(uint16_t len, \
                                                   uint8_t reason, \
                                                   uint8_t table_id, \
												   struct pof_flow_entry *pfe, \
                                                   uint32_t device_id, \
                                                   uint8_t *packet);
extern uint32_t pofdp_write_32value_to_field(uint32_t value, const struct pof_match *pm, \
											 struct pofdp_packet *dpp);
uint32_t pofdp_send_raw(struct pofdp_packet *dpp);
uint32_t pofdp_instruction_execute(POFDP_ARG);



#endif // _POF_DATAPATH_H_
