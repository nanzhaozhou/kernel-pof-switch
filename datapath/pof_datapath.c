#include <linux/if_ether.h> /* For ETH_P_ALL. */
#include <linux/netdevice.h>/* For struct packet_type. */
#include <linux/skbuff.h>/* For struct sk_buff. */
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/byteorder/generic.h>

#include "../include/pof_global.h"
#include "../include/pof_connection.h"
#include "../include/pof_byte_transfer.h"
#include "../include/pof_local_resource.h"
#include "../include/pof_datapath.h"
#include "../include/pof_log_print.h"

static uint32_t pofdp_forward(struct pofdp_packet *dp_packet, struct pof_instruction *first_ins);
static struct pof_datapath dp;
static struct packet_type pof_packet_type;

/* Kmalloc buf in packet data */
static uint32_t kmalloc_packet_data(struct pofdp_packet **dpp, uint32_t len){
    *dpp = (struct pofdp_packet *)kmalloc(sizeof(struct pofdp_packet), GFP_ATOMIC);
	if(*dpp == NULL){
		return POF_ERROR;
	}
	memset(*dpp, 0, sizeof(struct pofdp_packet));

	(*dpp)->buf = (uint8_t *)kmalloc(POFDP_PACKET_RAW_MAX_LEN, GFP_ATOMIC);
	if((*dpp)->buf == NULL){
		kfree(*dpp);
		return POF_ERROR;
	}
	memset((*dpp)->buf, 0, POFDP_PACKET_RAW_MAX_LEN);
	(*dpp)->ori_len = len;
	(*dpp)->left_len = (*dpp)->ori_len;
	(*dpp)->buf_offset = (*dpp)->buf;
	return POF_OK;
}

/* Kfree buf in packet data */
static uint32_t kfree_packet_data(struct pofdp_packet *dpp){
	if(dpp!=NULL && dpp->buf!=NULL){
		kfree(dpp->buf);
		dpp->buf = NULL;
		dpp->ori_len = 0;
		kfree(dpp);
	}

	return POF_OK;
}


/***********************************************************************
 * Initial the datapath module
 * Form:     pof_datapath_init(void)
 * Input:    NONE
 * Output:   NONE
 * Return:   POF_ERROR or POF_OK
 * Discribe: This function initial the datapath module, registering a ETH_P_ALL hook to the network stack.
 ***********************************************************************/
uint32_t pof_datapath_init(void){
	/* Add the hook */
	dev_add_pack(&pof_packet_type);
    return POF_OK;
}

/***********************************************************************
 * Destroy the datapath module
 * Form:     pof_datapath_destroy(void)
 * Input:    NONE
 * Output:   NONE
 * Return:   POF_OK
 * Discribe: This function initial the datapath module, removing a ETH_P_ALL hook from the network stack.
 ***********************************************************************/
uint32_t pof_datapath_destroy(void){
	/* Remove the hook */
	dev_remove_pack(&pof_packet_type);
    return POF_OK;
}

/* Set first instruction */
static void set_goto_first_table_instruction(struct pof_instruction *p)
{
	struct pof_instruction_goto_table *pigt = \
			(struct pof_instruction_goto_table *)p->instruction_data;

	/* Where is POFIT_GOTO_TABLE definition? TODO */
	p->type = POFIT_GOTO_TABLE;
	p->len = sizeof(pigt);
	pigt->next_table_id = POFDP_FIRST_TABLE_ID;
	return;
}

/*
   This function makes lazy skb cloning in hope that most of packets
   are discarded by BPF.

   Note tricky part: we DO mangle shared skb! skb->data, skb->len
   and skb->cb are mangled. It works because (and until) packets
   falling here are owned by current CPU. Output packets are cloned
   by dev_queue_xmit_nit(), input packets are processed by net_bh
   sequencially, so that if we return skb to original state on exit,
   we will not harm anyone.
 */

static int pof_packet_recv_hook(struct sk_buff *skb, struct net_device *dev,\
		      struct packet_type *pt, struct net_device *orig_dev){
    uint32_t ret, total_len;
	unsigned char *mac_header_ptr = NULL;
	struct pof_instruction first_ins[1] = {0};
	/* Defined in pof_global.h-->. */
    struct pof_port *port_ptr = NULL;
	struct pofdp_packet *dpp = NULL;

	/* Filter out unwanted packet */
	if(skb->pkt_type == PACKET_OUTGOING){
		return POF_OK;
	}

	if(skb->pkt_type == PACKET_LOOPBACK){
		goto out;
	}

	port_ptr = poflr_get_port_by_index((int32_t)skb->iif);
	if(!port_ptr){
		goto out;
	}

	/* Check whether the OpenFlow-enabled of the port is on or not. */
	if(port_ptr->of_enable == POFLR_PORT_DISABLE){
		goto out;
	}

	/* First need to recover ll header info. 
	 * Incoming packets have ll header pulled, push it back.
	 */
	if (dev->header_ops) {
		/* The device has an explicit notion of ll header,
		   exported to higher levels.
		 */
		mac_header_ptr = skb_mac_header(skb);
		total_len = skb->len + (skb->data - mac_header_ptr); 
	}else{
		/*
		 * Otherwise, the device hides datails of it frame
		 * structure, so that corresponding packet head
		 * never delivered to user.
		 */
		goto out;
	}

	/* Check the packet length. */
	if(total_len > POF_MTU_LENGTH){
		goto out;
	}

	/* Filter the received raw packet by some rules. */
	if(dp.filter(mac_header_ptr, port_ptr, skb->pkt_type) != POF_OK){
		goto out;
	}
		
	/* Store packet data, length, received port infomation into the dpp */
	ret = kmalloc_packet_data(&dpp, total_len);
	if(POF_OK != ret){
		goto out;
	}
	dpp->ori_port_id = port_ptr->port_id;
	memcpy(dpp->buf, mac_header_ptr, total_len);

	/* Now we can manipulate this dpp. */

	/* Check whether the first flow table exist. */
	if(POF_OK != poflr_check_flow_table_exist(POFDP_FIRST_TABLE_ID)){
		kfree_packet_data(dpp);
		goto out;
	}

	/* Set GOTO_TABLE instruction to go to the first flow table. */
	set_goto_first_table_instruction(first_ins);

	pofdp_forward(dpp, first_ins);

	kfree_packet_data(dpp);
	goto out;

out:
	/* Hedging of the deliver_skb() operation */
	kfree_skb(skb);
	return POF_OK;
}

/***********************************************************************
 * Promisc mode packet filter
 * Form:     static uint32_t pofdp_promisc(struct sk_buff *skb, pof_port *port_ptr)
 * Input:    packet data, port infomation
 * Output:   NONE
 * Return:   POF_OK
 * Discribe: This function filter the RAW packet received by the local
 *           physical net port.
 ***********************************************************************/
static uint32_t pofdp_promisc(unsigned char *mac_header_ptr, pof_port *port_ptr, uint8_t pkt_type){
    return POF_OK;
}


/***********************************************************************
 * NONE promisc mode packet filter
 * Form:     static uint32_t pofdp_no_promisc(struct sk_buff *skb, pof_port *port_ptr)
 * Input:    packet data, port infomation
 * Output:   NONE
 * Return:   POF_OK or Error code
 * Discribe: This function filter the RAW packet received by the local
 *           physical net port.
 ***********************************************************************/
static uint32_t pofdp_no_promisc(unsigned char *mac_header_ptr, pof_port *port_ptr, uint8_t pkt_type){
    uint8_t  *eth_daddr;
    uint8_t broadcast[POF_ETH_ALEN] = {
        0xff,0xff,0xff,0xff,0xff,0xff
    };

#ifdef POF_RECVRAW_DHWADDR_LOCAL
    eth_daddr = (uint8_t *)mac_header_ptr;
    if(memcmp(eth_daddr, port_ptr->hw_addr, POF_ETH_ALEN) != 0 && \
            memcmp(eth_daddr, broadcast, POF_ETH_ALEN) != 0){
		return POF_ERROR;
    }
#endif // POF_RECVRAW_DHWADDR_LOCAL

    if(pkt_type == PACKET_OTHERHOST){
        return POF_ERROR;
    }

    return POF_OK;
}

static uint32_t 
init_packet_metadata(struct pofdp_packet *dpp, struct pofdp_metadata *metadata, size_t len)
{
	if(len < sizeof *metadata){
		POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_METADATA_LEN_ERROR);
	}

	memset(metadata, 0, len);
	metadata->len = POF_HTONS(dpp->ori_len);
	metadata->port_id = dpp->ori_port_id;

	dpp->metadata_len = len;
	dpp->metadata = metadata;

	return POF_OK;
}

/***********************************************************************
 * Forward function
 * Form:     static uint32_t pofdp_forward(uint8_t *packet, \
 *                                         uint32_t len, \
 *                                         uint32_t port_id)
 * Input:    packet, length of packet
 * Output:   NONE
 * Return:   POF_OK or Error code
 * Discribe: This function forwards the packet between the flow tables.
 *           The new packet will be send into the MM0 table, which is
 *           head flow table. Then according to the matched flow entry,
 *           the packet will be forwarded between the other flow tables
 *           or execute the instruction and action corresponding to the
 *           matched flow entry.
 * NOTE:     This function will be over in these situations: 1, All of
 *           the instruction has been executed. 2, The packet has been
 *           droped, send upward to the Controller, or output through
 *           the specified local physical port. 3, Any ERROR has occurred
 *           during the process.
 ***********************************************************************/
static uint32_t pofdp_forward(struct pofdp_packet *dpp, struct pof_instruction *first_ins)
{
	/* Defined in pof_datapath.h-->. */
	uint8_t metadata[POFDP_METADATA_MAX_LEN] = {0};
	uint32_t ret;

	/* Initialize the metadata. */
	ret = init_packet_metadata(dpp, (struct pofdp_metadata *)metadata, sizeof(metadata));
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	/* Set the first instruction to the Datapath packet. */
	dpp->ins = first_ins;
	dpp->ins_todo_num = 1;

	/* Instruction entry. */
	ret = pofdp_instruction_execute(dpp);
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	return POF_OK;
}

/***********************************************************************
 * Send packet upward to the Controller
 * Form:     uint32_t pofdp_send_packet_in_to_controller(uint16_t len, \
 *                                                       uint8_t reason, \
 *                                                       uint8_t table_id, \
 *                                                       uint64_t cookie, \
 *                                                       uint32_t device_id, \
 *                                                       uint8_t *packet)
 * Input:    packet length, upward reason, current table id, cookie,
 *           device id, packet data
 * Output:   NONE
 * Return:   POF_OK or Error code
 * Discribe: This function send the packet data upward to the controller.
 *           It assembles the packet data, length, reason, table id,
 *           cookie and device id with format of struct pof_packet_in,
 *           and encapsulate to a new openflow packet. Then the new packet
 *           will be send to the mpu module in order to send upward to the
 *           Controller.
 ***********************************************************************/
uint32_t pofdp_send_packet_in_to_controller(uint16_t len, \
                                            uint8_t reason, \
                                            uint8_t table_id, \
											struct pof_flow_entry *pfe, \
                                            uint32_t device_id, \
                                            uint8_t *packet)
{
    pof_packet_in packetin = {0};
    uint32_t      packet_in_len;

    /* The length of the packet in data upward to the Controller is the real length
     * instead of the max length of the packet_in. */
    packet_in_len = sizeof(pof_packet_in) - POF_PACKET_IN_MAX_LENGTH + len;

    /* Check the packet length. */
    if(len > POF_PACKET_IN_MAX_LENGTH){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_SOFTWARE_FAILED, POF_PACKET_LEN_ERROR, g_upward_xid++);
    }

    packetin.buffer_id = 0xffffffff;
    packetin.total_len = len;
    packetin.reason = reason;
    packetin.table_id = table_id;
	if(NULL != pfe){
		packetin.cookie = pfe->cookie & pfe->cookie_mask;
	}else{
		packetin.cookie = 0;
	}
    packetin.device_id = device_id;
    memcpy(packetin.data, packet, len);
    pof_HtoN_transfer_packet_in(&packetin);

    if(POF_OK != pofec_reply_msg(POFT_PACKET_IN, g_upward_xid++, packet_in_len, (uint8_t *)&packetin)){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_SOFTWARE_FAILED, POF_WRITE_MSG_QUEUE_FAILURE, g_recv_xid);
    }

    return POF_OK;
}

/***********************************************************************
 * Send packet out function
 * Form:     uint32_t pofdp_send_raw(uint8_t *buf, uint32_t len, uint32_t port_id)
 * Input:    packet data, packet length, output port id
 * Output:   NONE
 * Return:   POF_OK or Error code
 * Discribe: This function send the packet data out through the port
 *           corresponding the port_id. The length of packet data is len.
 *           It assembles the packet data, the packet length
 *           and the output port id with format of struct pofdp_packet,
 *           and write it to the send queue. Caller should make sure that
 *           output_packet_offset plus output_packet_len is less than the
 *           whole packet_len, and that output_metadata_offset plus 
 *           output_metadata_len is less than the whole metadata_len.
 ***********************************************************************/
uint32_t pofdp_send_raw(struct pofdp_packet *dpp){
	struct net_device *dev = NULL;
	struct sk_buff *skb = NULL;
	struct pof_port *outPort=NULL;
	uint32_t ret = POF_OK;
	/* Malloc the output data memery which will be freed in 
	 * pofdp_send_raw_task. */
	uint8_t *data = (uint8_t *)kmalloc(dpp->output_whole_len, GFP_ATOMIC);
	if(data == NULL){
		return POF_ERROR;
	}
    memset(data, 0, dpp->output_whole_len);

	/* Copy metadata to output buffer. */
    pofdp_copy_bit((uint8_t *)dpp->metadata, data, dpp->output_metadata_offset, \
			dpp->output_metadata_len * POF_BITNUM_IN_BYTE);
	/* Copy packet to output buffer right behind metadata. */
    memcpy(data + dpp->output_metadata_len, dpp->buf + dpp->output_packet_offset, dpp->output_packet_len);
	dpp->buf_out = data;

    /* Check the packet lenght. */
    if(dpp->output_whole_len > POF_MTU_LENGTH){
		kfree(data);
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_SOFTWARE_FAILED, POF_PACKET_LEN_ERROR, g_upward_xid++);
    }

	outPort = poflr_get_port_by_index(dpp->output_port_id);
	if(!outPort)
	{
		kfree(data);
		return POF_ERROR;
	}

	dev = dev_get_by_name(&init_net, outPort->name); 
	if(!dev)
	{
		kfree(data);
		return POF_ERROR;
	}
	skb = alloc_skb(POF_MTU_LENGTH, GFP_ATOMIC);
	skb_put(skb, dpp->output_whole_len);
	memcpy(skb->data, dpp->buf_out, dpp->output_whole_len );
	skb->dev = dev;

	if(dev_queue_xmit(skb) != NET_XMIT_SUCCESS)
	{
		kfree(data);
		return POF_ERROR;
	}
	kfree(data);

    return POF_OK;
}


/* Global datapath structure. */
static struct pof_datapath dp = {
    pofdp_no_promisc,
    pofdp_promisc,
#ifdef POF_PROMISC_ON
    pofdp_promisc,
#else // POF_PROMISC_ON
    pofdp_no_promisc,
#endif // POF_PROMISC_ON
};

static struct packet_type pof_packet_type = {
	__constant_htons(ETH_P_ALL),/* All 3Layer packet type. */ 
	NULL,     /* All devices. */
	pof_packet_recv_hook, /* Hook function. */
	(void *)1,
	NULL,
};




