#include <linux/types.h> /* For uint32_t. */
#include <linux/slab.h>  /* For kmalloc kfree. */
#include <linux/string.h>/* For strcpy. */
#include <linux/netdevice.h> /* For struct net_device. */
#include <linux/skbuff.h>/* For struct sk_buff. */
#include <linux/inetdevice.h>/* For struct in_device & struct in_ifaddr. */
#include <linux/kthread.h> /* For kthread_should_stop. */ 
#include <linux/kernel.h>/* For sprintf. */

#include "../include/pof_local_resource.h"
#include "../include/pof_global.h"
#include "../include/pof_connection.h"
#include "../include/pof_log_print.h"
#include "../include/pof_byte_transfer.h"


enum poflr_port_compare_flag{
	POFPCF_DEFAULT = 0x00,
	POFPCF_SAME   = 0x01,
	POFPCF_MODIFY = 0x02,
	POFPCF_ADD    = 0x03,
};


/* The max number of local physical ports. */
static uint32_t poflr_device_port_num_max = POFLR_DEVICE_PORT_NUM_MAX;

/* Port number actually. */
uint16_t poflr_port_num = 0;

/* Port name array. */
char **poflr_port_name = NULL;

/* Port IP address. */
char **poflr_port_ipaddr_str = NULL;

/* Ports. */
pof_port *poflr_port = NULL;
pof_port *poflr_port_new = NULL;

/* Functions */
static uint32_t poflr_get_port_num_name(char **name, uint16_t *num);
static uint32_t poflr_get_ip_by_name(const char *name, char *ip_str);
static uint32_t poflr_set_port(const char *name, pof_port *p);
static uint32_t poflr_get_hwaddr_index_by_name(const char *name, \
                                               unsigned char *hwaddr, \
                                               uint32_t *index);
static uint32_t poflr_check_port_up(const char *name);
static uint32_t poflr_check_port_link(const char *name);
static uint32_t poflr_port_detect_main(char **name_old, \
		                               uint16_t *num_old, \
		                               pof_port *p_old, \
									   char **name_new, \
									   uint16_t *num_new,\
									   pof_port *p_new, \
									   uint8_t *flag);
static uint32_t poflr_port_detect_info(pof_port *p, char **name, uint16_t *num);
static uint32_t poflr_port_compare_info(pof_port *p_old, \
		                                pof_port *p_new, \
										uint16_t num_new, \
										uint16_t num_old, \
										uint8_t *flag);
static uint32_t poflr_port_compare_info_single(pof_port *p_old, pof_port *p_new, uint16_t num_old, uint8_t *flag);
static uint32_t poflr_port_two_port_is_one(pof_port *p_old, pof_port *p_new);
static uint32_t poflr_port_detect_same(pof_port *p_old, pof_port *p_new, uint8_t *flag);
static uint32_t poflr_port_detect_modify(pof_port *p_old, pof_port *p_new, uint8_t *flag);
static uint32_t poflr_port_report(uint8_t reason, pof_port *p);
static uint32_t poflr_port_detect_add(pof_port *p_old, pof_port *p_new, uint8_t *flag);
static uint32_t poflr_port_compare_check_old(pof_port *p_old, uint16_t num_old, uint8_t *flag);
static uint32_t poflr_port_update(pof_port *p_old, pof_port *p_new, uint16_t *num_old, uint16_t *num_new);
static uint32_t poflr_port_detect_delete(pof_port *p_old);




/* Set the max number of ports. */
uint32_t poflr_set_port_number_max(uint32_t port_num_max){
	poflr_device_port_num_max = port_num_max;
	return POF_OK;
}


/***********************************************************************
 * Initialize the local physical net port infomation.
 * Form:     uint32_t poflr_init_port(void)
 * Input:    NONE
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will initialize the local physical net port
 *           infomation, including port name, port index, port MAC address
 *           and so on.
 ***********************************************************************/
uint32_t poflr_init_port(void){
    uint32_t i, j, ret = POF_OK;
    uint16_t ulPort;

	/* Global var. */
    poflr_port_num = 0;

	/* Use kmalloc to get memory, kfree to free memory. */
	poflr_port_name = (char **)kmalloc(poflr_device_port_num_max * sizeof(char *), GFP_KERNEL);

	POF_KMALLOC_ERROR_HANDLE_RETURN_NO_UPWARD(poflr_port_name);
	for(i=0; i<poflr_device_port_num_max; i++){
		poflr_port_name[i] = (char *)kmalloc(MAX_IF_NAME_LENGTH * sizeof(char), GFP_KERNEL);
		if(NULL == poflr_port_name[i]){
			for(j=0; j<i; j++)
				kfree(poflr_port_name[j]);
			kfree(poflr_port_name);
			POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_ALLOCATE_RESOURCE_FAILURE);
		}
	}

	/* Get local port number and name. */
    ret = poflr_get_port_num_name(poflr_port_name, &poflr_port_num);
    POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	/* Get local port ip address. */
    poflr_port_ipaddr_str = (char **)kmalloc(poflr_port_num * sizeof(char *), GFP_KERNEL);
	POF_KMALLOC_ERROR_HANDLE_RETURN_NO_UPWARD(poflr_port_ipaddr_str);

	/* Highest port abstraction */
    poflr_port = (pof_port *)kmalloc(poflr_port_num * sizeof(pof_port), GFP_KERNEL);
	if(NULL == poflr_port){
		kfree(poflr_port_ipaddr_str);
        POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_ALLOCATE_RESOURCE_FAILURE);
	}
	memset(poflr_port, 0, poflr_port_num * sizeof(pof_port));

    /* Traverse all of the ports. */
    for (ulPort = 0; ulPort < poflr_port_num; ulPort++){

        /* Get port's IP address. */
		/* POF_IP_ADDRESS_STRING_LEN see pof_connection.h--> */
        poflr_port_ipaddr_str[ulPort] = (char *)kmalloc(POF_IP_ADDRESS_STRING_LEN * sizeof(char), GFP_KERNEL);
		if(NULL == poflr_port_ipaddr_str[ulPort]){
			for(i=0; i<ulPort; i++){
				kfree(poflr_port_ipaddr_str[ulPort]);
			}
			kfree(poflr_port_ipaddr_str);
			kfree(poflr_port);
			POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_ALLOCATE_RESOURCE_FAILURE);
		}

		/* Get port ip string by port name. */
        ret = poflr_get_ip_by_name(poflr_port_name[ulPort], poflr_port_ipaddr_str[ulPort]);

		/* Set the highest port abstraction by port name */
		ret |= poflr_set_port(poflr_port_name[ulPort], &poflr_port[ulPort]);
		if(POF_OK != ret){
			POF_DEBUG_PRINTK();
			for(i=0; i<=ulPort; i++){
				kfree(poflr_port_ipaddr_str[ulPort]);
			}
			kfree(poflr_port_ipaddr_str);
			kfree(poflr_port);
			return ret;
		}
    }

    return POF_OK;
}


/* Get port number and name from kernel space */
static uint32_t 
poflr_get_port_num_name(char **name, uint16_t *num)
{
    uint16_t count = 0;
	struct net_device *dev;

	dev = first_net_device(&init_net);
	while (dev) {
            if(strcmp(dev->name, "lo")==0){
				dev = next_net_device(dev);
                continue;
            }
            strcpy(name[count], dev->name);
            count++;

			dev = next_net_device(dev);
	}
    *num = count;
    return POF_OK;
}


/***********************************************************************
 * Get the HWaddr and the index of the local physical ports.
 * Form:     uint32_t poflr_get_ip_by_name(const char *name, char *ip_str)
 * Input:    port name string
 * Output:   HWaddr, port index, ip address
 * Return:   POF_OK or ERROR code
 * Discribe: This function will get the ip address string of the local 
 *           physical ports by the port name string.
 ***********************************************************************/
static uint32_t poflr_get_ip_by_name(const char *name, char *ip_str){
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *in_info;
	__u8 *addr;

	dev = dev_get_by_name(&init_net, name);
	if(dev==NULL)
	{
		return POF_ERROR;
	}
	in_dev = (struct in_device *)dev->ip_ptr;
	/* Just get the first ip string */
	in_info = (struct in_ifaddr *)in_dev->ifa_list;
	addr = (char *)&in_info->ifa_local; 
	sprintf(ip_str, "%u.%u.%u.%u", (__u32)addr[0],(__u32)addr[1],(__u32)addr[2],(__u32)addr[3]);

    return POF_OK;
}

/* Set the highest port abstraction by port name. */
static uint32_t poflr_set_port(const char *name, pof_port *p){
	uint32_t ret = POF_OK;

	/* Get port hardware address and index number. */
	ret = poflr_get_hwaddr_index_by_name(name, p->hw_addr, &p->port_id);
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	/* Check whether the port is up. */
	/* Check whether the link is up. */
	if( (POF_OK == poflr_check_port_up(name)) && \
			(POF_OK == poflr_check_port_link(name)) ){
		/* Defined in pof_global.h--> */
		p->state = POFPS_LIVE;
	}
	else{
		/* Defined in pof_global.h--> */
		p->state = POFPS_LINK_DOWN;
	}


	/* Fill the port's other infomation. */
	p->config = 0;
	/* Defined in pof_global.h-->. */
	p->curr = POFPF_10MB_HD | POFPF_10MB_FD;
	/* Defined in pof_local_resource.h-->. */
	p->of_enable = POFLR_PORT_DISABLE;
	p->device_id = g_poflr_dev_id;
	p->supported = 0xffffffff;
	p->advertised = POFPF_10MB_FD | POFPF_100MB_FD;
	p->peer = POFPF_10MB_FD | POFPF_100MB_FD;
	strcpy((char *)p->name, name);

	return POF_OK;
}

/***********************************************************************
 * Get the HWaddr and the index of the local physical ports.
 * Form:     uint32_t poflr_get_hwaddr_index_by_name(const char *name, \
 *                                                   unsigned char *hwaddr, \
 *                                                   uint32_t *index)
 * Input:    port name string
 * Output:   HWaddr, port index, ip address
 * Return:   POF_OK or ERROR code
 * Discribe: This function will get the HWaddr, the index and the ip 
 *           address of the local physical ports by the port name string.
 ***********************************************************************/
static uint32_t poflr_get_hwaddr_index_by_name(const char *name, \
                                               unsigned char *hwaddr, \
                                               uint32_t *index)
{
	struct net_device *dev;
	dev = dev_get_by_name(&init_net, name);
	if(dev==NULL)
	{
		return POF_ERROR;
	}
	sprintf(hwaddr, "%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x", dev->dev_addr[0], dev->dev_addr[1],dev->dev_addr[2],dev->dev_addr[3],dev->dev_addr[4],dev->dev_addr[5]);
	*index=dev->ifindex;
	return POF_OK;
}


/* Check whether the port is up. */
static uint32_t poflr_check_port_up(const char *name){
	struct net_device *dev;

	dev = dev_get_by_name(&init_net, name);
	if(dev==NULL)
	{
		return POF_ERROR;
	}
	if(dev->flags & IFF_UP)
	{
		return POF_OK;
	}
	return POF_ERROR;
}

/* Check whether the link is up. */
static uint32_t poflr_check_port_link(const char *name){
	struct net_device *dev;

	dev = dev_get_by_name(&init_net, name);
	if(dev==NULL)
	{
		return POF_ERROR;
	}
	if(dev->flags & IFF_RUNNING)
	{
		return POF_OK;
	}
	return POF_ERROR;
}

/* Disable all port OpenFlow forwarding. */
uint32_t poflr_disable_all_port(void){
	uint32_t i;

    for(i = 0; i < poflr_port_num; i++){
        poflr_port[i].of_enable = POFLR_PORT_DISABLE;
    }

	return POF_OK;
}

/***********************************************************************
 * Get the hardware address of the local physical net ports by IP address.
 * Form:     uint32_t poflr_get_hwaddr_by_ipaddr(uint8_t *hwaddr, 
 *                                               char *ipaddr_str, 
 *                                               uint8_t *port_id_ptr)
 * Input:    ipaddr_str
 * Output:   hwaddr
 * Return:   POF_OK or Error code
 * Discribe: This function will get the hardware address of the local
 *           physical net ports by IP address.
 ***********************************************************************/
uint32_t poflr_get_hwaddr_by_ipaddr(uint8_t *hwaddr, char *ipaddr_str, uint8_t *port_id_ptr){
    uint32_t i;

    /* Traverse all of the ports to find the one matching the 'ipaddr_str'. */
    for(i=0; i<poflr_port_num; i++){
        if(strcmp(ipaddr_str, poflr_port_ipaddr_str[i]) == POF_OK){
            memcpy(hwaddr, poflr_port[i].hw_addr, POF_ETH_ALEN);
			*port_id_ptr = poflr_port[i].port_id;
            return POF_OK;
        }
    }

    /* Error occurred and returned if there is no port matching the 'ipaddr_str'. */
    POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_GET_PORT_INFO_FAILURE);
}

/* Get port number. */
uint32_t poflr_get_port_number(uint16_t *port_number_ptr){
	*port_number_ptr = poflr_port_num;
	return POF_OK;
}

/* Get ports. */
uint32_t poflr_get_port(pof_port **port_ptrptr){
	*port_ptrptr = poflr_port;
	return POF_OK;
}

/***********************************************************************
 * Modify the OpenFlow function enable flag of the port.
 * Form:     uint32_t poflr_port_openflow_enable(uint8_t port_id, uint8_t ulFlowEnableFlg)
 * Input:    port id, OpenFlow enable flag
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will modify the OpenFlow function flag of the
 *           port.
 ***********************************************************************/
uint32_t poflr_port_openflow_enable(uint8_t port_id, uint8_t ulFlowEnableFlg){
    pof_port *tmp_port;
    uint32_t ret = POF_ERROR, i;

    /* Find the port with 'port_id' to change the flag 'of_enable'. */
    for(i=0; i<poflr_port_num; i++){
        tmp_port = &poflr_port[i];
        if(tmp_port->port_id == port_id){
            tmp_port->of_enable = ulFlowEnableFlg;
            ret = POF_OK;
        }
    }

    /* Error occurred and returned if there is no port with 'port_id'. */
    if(ret == POF_ERROR){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_PORT_MOD_FAILED, POFPMFC_BAD_PORT_ID, g_recv_xid);
    }

    printk(KERN_DEBUG "[POF_DEBUG_INFO:] Port openflow enable MOD SUC!\n");
    return POF_OK;
}

/* Detect all of ports, and report to Controller if any change. */
int poflr_port_detect_task(void){
	int ret = POF_OK, i;
	char **name_new;
	uint16_t num_new = 0;
	uint8_t *flag;
	/* TODO */

	flag = (uint8_t *)kmalloc(poflr_device_port_num_max * sizeof(uint8_t), GFP_KERNEL);
	if(NULL == flag){
		terminate_handler();
	}

	poflr_port_new = (pof_port *)kmalloc(poflr_device_port_num_max * sizeof(pof_port), GFP_KERNEL);
	if((NULL == poflr_port_new)){
		terminate_handler();
	}

	name_new = (char **)kmalloc(poflr_device_port_num_max * sizeof(char *), GFP_KERNEL);
	if(NULL == name_new){
		terminate_handler();
	}

	for(i=0; i<poflr_device_port_num_max; i++){
		name_new[i] = (char *)kmalloc(MAX_IF_NAME_LENGTH * sizeof(char), GFP_KERNEL);
		if(NULL == name_new[i]){
			terminate_handler();
		}
	}

	while(1){
		/* exit thread */
		if(kthread_should_stop()){
			printk(KERN_DEBUG "[POF_DEBUG_INFO] pofsc_send_msg_task going to exit!\n");
			break;
		}

		/* Every 5secs */
		pofbf_task_delay(5000);
		memset(poflr_port_new, 0, poflr_device_port_num_max * sizeof(pof_port));
		memset(flag, 0, poflr_device_port_num_max * sizeof(uint8_t));
		for(i=0; i<poflr_device_port_num_max; i++){
			memset(name_new[i], 0, MAX_IF_NAME_LENGTH);
		}
		num_new = 0;

		ret = poflr_port_detect_main(poflr_port_name, &poflr_port_num, poflr_port, \
				                     name_new, &num_new, poflr_port_new, flag);
		POF_CHECK_RETVALUE_TERMINATE(ret);

		ret = poflr_port_update(poflr_port, poflr_port_new, &poflr_port_num, &num_new);
	}
	return ret;
}

/* What if there is a new port added, it seems we have't
 * kmalloc space for this new port, needs to TEST! */
static uint32_t poflr_port_detect_main(char **name_old, \
		                               uint16_t *num_old, \
		                               pof_port *p_old, \
									   char **name_new, \
									   uint16_t *num_new, \
									   pof_port *p_new, \
									   uint8_t *flag){
	uint32_t ret = POF_OK;

	/* Detect all of ports infomation right now. */
	ret = poflr_port_detect_info(p_new, name_new, num_new);
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	/* Compare the ports infomation. */
	ret = poflr_port_compare_info(p_old, p_new, *num_new, *num_old, flag);
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	ret = poflr_port_compare_check_old(p_old, *num_old, flag);
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	return POF_OK;
}

static uint32_t poflr_port_detect_info(pof_port *p, char **name, uint16_t *num){
	uint32_t ret = POF_OK, i;

	ret = poflr_get_port_num_name(name, num);
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	for(i=0; i<*num; i++){
		poflr_set_port(name[i], p+i);
	}
	
	return POF_OK;
}

static uint32_t poflr_port_compare_info(pof_port *p_old, \
		                                pof_port *p_new, \
										uint16_t num_new, \
										uint16_t num_old, \
										uint8_t *flag)
{
	uint32_t ret = POF_OK, i;

	for(i=0; i<num_new; i++){
		/* Check the port in the old ports. */
		ret = poflr_port_compare_info_single(p_old, p_new+i, num_old, flag);
		if(POF_OK == ret){
			/* The port is already have. */
			continue;
		}
		/* ret != POF_OK means the port is a new port, need to report to Controller. */
		ret = poflr_port_detect_add(p_old, p_new+i, flag);
		POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);
	}

	return POF_OK;
}

static uint32_t poflr_port_compare_info_single(pof_port *p_old, pof_port *p_new, uint16_t num_old, uint8_t *flag){
	uint32_t ret = POF_OK, i;
	pof_port *p;
	
	for(i=0; i<num_old; i++){
		p = (pof_port *)(p_old + i);
		/* Not the same port, continue */
		if(POF_OK != poflr_port_two_port_is_one(p, p_new)){
			continue;
		}
		/* Same port */
		p_new->of_enable = p->of_enable;
		if(POF_OK == (ret = memcmp(p, p_new, sizeof(pof_port)))){
			ret = poflr_port_detect_same(p, p_new, flag + i);
		}else{
			ret = poflr_port_detect_modify(p, p_new, flag + i);
		}
		POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);
		return POF_OK;
	}

	return POF_ERROR;
}

static uint32_t poflr_port_two_port_is_one(pof_port *p_old, pof_port *p_new){
	uint32_t ret;

	/* Two ports is one, if they have same name. return POF_OK */
	ret = strncmp(p_old->name, p_new->name, MAX_IF_NAME_LENGTH);
	if(POF_OK == ret){
		return POF_OK;
	}
	return POF_ERROR;
}

static uint32_t poflr_port_detect_same(pof_port *p_old, pof_port *p_new, uint8_t *flag){
	*flag = POFPCF_SAME;
	return POF_OK;
}

static uint32_t poflr_port_detect_modify(pof_port *p_old, pof_port *p_new, uint8_t *flag){
	uint32_t ret = POF_OK;

	/* Report to controller */
	/* POFPR_MODIFY defined in pof_global./h--> */
	ret = poflr_port_report(POFPR_MODIFY, p_new);
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	/* Defined above */
	*flag = POFPCF_MODIFY;
	return POF_OK;
}

static uint32_t poflr_port_report(uint8_t reason, pof_port *p){
	/* Defined in pof_global.h--> */
    pof_port_status port_status = {0};

	port_status.reason = reason;
	memcpy(&port_status.desc, (uint8_t *)p, sizeof(pof_port));
	/* Declared in pof_byte_transfer.h--> */
	pof_HtoN_transfer_port_status(&port_status);

	/* Declared in pof_connection.h--> */
	if(POF_OK != pofec_reply_msg(POFT_PORT_STATUS, g_upward_xid, sizeof(pof_port_status), (uint8_t *)&port_status)){
		POF_ERROR_HANDLE_RETURN_UPWARD(POFET_SOFTWARE_FAILED, POF_WRITE_MSG_QUEUE_FAILURE, g_recv_xid);
	}

    return POF_OK;
}

static uint32_t poflr_port_detect_add(pof_port *p_old, pof_port *p_new, uint8_t *flag){
	uint32_t ret = POF_OK;

	/* Report to controller-->. */
	ret = poflr_port_report(POFPR_ADD, p_new);
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);
	return POF_OK;
}

static uint32_t poflr_port_compare_check_old(pof_port *p_old, uint16_t num_old, uint8_t *flag){
	uint32_t ret = POF_OK, i;

	for(i=0; i<num_old; i++){
		if(*(flag+i) != POFPCF_DEFAULT){
			continue;
		}
		ret = poflr_port_detect_delete(p_old + i);
		POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);
	}

	return POF_OK;
}

static uint32_t poflr_port_detect_delete(pof_port *p_old){
	uint32_t ret = POF_OK;

	ret = poflr_port_report(POFPR_DELETE, p_old);
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	return POF_OK;
}

static uint32_t poflr_port_update(pof_port *p_old, pof_port *p_new, uint16_t *num_old, uint16_t *num_new){
	uint32_t i;

	for(i=0; i<*num_new; i++){
		memcpy(p_old+i, p_new+i, sizeof(pof_port));
	}
	*num_old = *num_new;

	return POF_OK;
}

uint32_t
poflr_check_port_index(uint32_t id)
{
	uint32_t i;

	for(i=0; i<poflr_port_num; i++){
		if(id == poflr_port[i].port_id){
			return POF_OK;
		}
	}

	//printk(KERN_DEBUG "[POF_DEBUG_INFO] Output port with index %u is invalid.", id);
	POF_ERROR_HANDLE_RETURN_UPWARD(POFET_BAD_ACTION, POFBAC_BAD_OUT_PORT, g_upward_xid++);
}


/* Get global port by index */
struct pof_port*
poflr_get_port_by_index(int32_t id)
{
	uint32_t i;

	for(i=0; i<poflr_port_num; i++){
		if(id == poflr_port[i].port_id){
			return &poflr_port[i];
		}
	}

	//printk(KERN_DEBUG "[POF_DEBUG_INFO] Port with index %u is invalid.", id);
	return NULL;
}



