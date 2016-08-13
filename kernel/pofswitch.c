#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/types.h> /* For uint32_t. */
#include <linux/kthread.h>  
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/net.h> /* For sock_create. */
#include <linux/inet.h> /* For in_aton. */
#include <linux/in.h> /* For struct sockaddr_in. */
#include <linux/string.h> /* For strncpy */
#include <net/inet_sock.h>/* For struct inet_sock. */
#include <linux/byteorder/generic.h>/* For htons. */ 
#include <linux/time.h>/* For do_gettimeofday. */

#include "../include/pof_local_resource.h"
#include "../include/pof_connection.h"
#include "../include/pof_log_print.h"
#include "../include/pof_common.h"
#include "../include/pof_global.h"
#include "../include/pof_byte_transfer.h"
#include "../include/pof_datapath.h"

/* MODULE PARMETERS. */
static char *ctrl_ip="192.168.1.1";
static int conn_port=6633;
static int mm_table_number=10;
static int lpm_table_number=10;
static int em_table_number=5;
static int dt_table_number=20;
static int flow_table_size=6000;
static int flow_table_key_length=320;
static int meter_number=1024;
static int counter_number=521;
static int group_number=1024;
static int device_port_number_max=20;


/* MODULE_PARM_DESC. */
module_param(ctrl_ip, charp, 0000);
MODULE_PARM_DESC(ctrl_ip, "ip address of the pof controller");
module_param(conn_port, int, 0000);
MODULE_PARM_DESC(conn_port, "tcp port of the pof controller");
module_param(mm_table_number, int, 0000);
MODULE_PARM_DESC(mm_table_number, "number of MM table");
module_param(lpm_table_number, int, 0000);
MODULE_PARM_DESC(lpm_table_number, "number of LPM table");
module_param(em_table_number, int, 0000);
MODULE_PARM_DESC(em_table_number, "number of EM table");
module_param(dt_table_number, int, 0000);
MODULE_PARM_DESC(dt_table_number, "number of DT table");
module_param(flow_table_size, int, 0000);
MODULE_PARM_DESC(flow_table_size, "size of flow table");
module_param(flow_table_key_length, int, 0000);
MODULE_PARM_DESC(flow_table_key_length, "key length of flow table");
module_param(meter_number, int, 0000);
MODULE_PARM_DESC(meter_number, "number of meter element");
module_param(counter_number, int, 0000);
MODULE_PARM_DESC(counter_number, "number of counter element");
module_param(group_number, int, 0000);
MODULE_PARM_DESC(group_number, "number of group element");
module_param(device_port_number_max, int, 0000);
MODULE_PARM_DESC(device_port_number_max, "max number of the device port");

/* Description of device connection. */
/* Defined in pof_connection.h-->. */
volatile pofsc_dev_conn_desc pofsc_conn_desc;

/* Timer interval. */
static uint32_t pofsc_echo_interval = POF_ECHO_INTERVAL;

/* Controller ip. */
static char pofsc_controller_ip_addr[POF_IP_ADDRESS_STRING_LEN] = "192.168.1.1";

/* Controller port. */
static uint16_t pofsc_controller_port=POF_CONTROLLER_PORT_NUM;

/* The max retry time of cnnection. */
static uint32_t pofsc_conn_max_retry=POF_CONNECTION_MAX_RETRY_TIME;

/* The retry interval of cnnection if connect fails. */
static uint32_t pofsc_conn_retry_interval = POF_CONNECTION_RETRY_INTERVAL;

/* Main task struct pointer. */
static struct task_struct *pofsc_main_task_ptr;

/* Send message task struct pointer. */
static struct task_struct *pofsc_send_task_ptr;

/* Ports detecting task struct pointer. */
static struct task_struct *pofsc_detectport_task_ptr;

/* For sending echo timer. */
static struct timer_list exp_timer;

/* Error message. */
/* Defined in pof_global.h-->. */
static pof_error pofsc_protocol_error;

/* Openflow connect state string. */
static char *pofsc_state_str[] = {
    "POFCS_CHANNEL_INVALID",
    "POFCS_CHANNEL_CONNECTING",
    "POFCS_CHANNEL_CONNECTED",
    "POFCS_HELLO",
    "POFCS_REQUEST_FEATURE",
    "POFCS_SET_CONFIG",
    "POFCS_REQUEST_GET_CONFIG",
    "POFCS_CHANNEL_RUN",
};

/* Openflow action id. Not static. */
/* Defined in pof_common.h--> */
uint32_t g_upward_xid = POF_INITIAL_XID;



/* Local functions */
static uint32_t pofsc_init(void);
static uint32_t pofsc_destroy(void);
static uint32_t pofsc_set_conn_attr(const char *controller_ip, uint16_t port, uint32_t retry_max, uint32_t retry_interval);
static uint32_t pofsc_set_controller_ip(char *ip_str);
static uint32_t pofsc_set_controller_port(uint16_t port);
static void pofsc_start_timer(void);
static void pofsc_echo_timer(uint32_t timer_id, int arg);
static int pofsc_main_task(void *arg_ptr);
static int pofsc_send_msg_task(void *arg_ptr);
static uint32_t pofsc_create_socket(struct socket **sock_ptr);
static uint32_t pofsc_connect(struct socket *sock, char *server_ip, uint16_t port);
static uint32_t pofsc_build_header(pof_header *header, uint8_t type, uint16_t len, uint32_t xid);
static uint32_t pofsc_send(struct socket *sock, char* buf, int len);
static uint32_t pofsc_performance_after_ctrl_disconn(void);
static uint32_t pofsc_recv(struct socket* sock, char* buf, int buflen, int* plen);
static uint32_t pofsc_set_error(uint16_t type, uint16_t code);
static uint32_t pofsc_run_process(char *message, uint16_t len);
static uint32_t pofsc_build_error_msg(char *message, uint16_t *len_p);


/***********************************************************************
 * Init function of the module. 
 * Form:     static int __init pofswitch_init(void)
 * Input:    NONE 
 * Output:   NONE
 * Return:   NONE
 * Discribe: This function will init the switch configurations by 
 *           parameters passed from userspace, also init the local
 *           resources, start neccesary tasks, timer and message queue,
 *           finally add a hook to the network stack.
 ***********************************************************************/
static int __init pofswitch_init(void)
{
	uint32_t ret = POF_OK;

	printk(KERN_INFO "[POF_DEBUG_INFO] Module pofswitch going to be loaded.\n");

	/* Init local configurations. */
	pofsc_set_controller_ip((char *)ctrl_ip);
	pofsc_set_controller_port((uint16_t)conn_port);
	poflr_set_MM_table_number((uint8_t)mm_table_number);
	poflr_set_LPM_table_number((uint8_t)lpm_table_number);
	poflr_set_EM_table_number((uint8_t)em_table_number);
	poflr_set_DT_table_number((uint8_t)dt_table_number);
	poflr_set_flow_table_size((uint32_t)flow_table_size);
	poflr_set_key_len((uint32_t)flow_table_key_length);
	poflr_set_meter_number((uint32_t)meter_number);
	poflr_set_counter_number((uint32_t)counter_number);
	poflr_set_group_number((uint32_t)group_number);
	poflr_set_port_number_max((uint32_t)device_port_number_max);

	/* Init the switch. */
    ret = pof_localresource_init();
    POF_CHECK_RETVALUE_TERMINATE(ret);

    /* Start OpenFlow communication module in Soft Switch. */
    ret = pofsc_init();
    POF_CHECK_RETVALUE_TERMINATE(ret);

    /* Delay for finishing the initlization started above. */
    pofbf_task_delay(1000);


#ifdef POF_DATAPATH_ON
    /* Start datapath module in Soft Switch. */
    ret = pof_datapath_init();
    POF_CHECK_RETVALUE_TERMINATE(ret);
#endif

	return 0;
}

/***********************************************************************
 * Exit function of the module 
 * Form:     static void __exit pofswitch_exit(void)  
 * Input:    NONE 
 * Output:   NONE
 * Return:   NONE
 * Discribe: This function will destroy the switch, stop tasks, delete
 *           timer and message queue, finally remove the hook to the 
 *           network stack.
 ***********************************************************************/
static void __exit pofswitch_exit(void)
{
	printk(KERN_INFO "[POF_DEBUG_INFO] Module pofswitch going to be unloaded.\n");
	terminate_handler();
}

/***********************************************************************
 * Start the OpenFlow communication module in Soft Switch.
 * Form:     uint32_t pofsc_init(void)
 * Input:    NONE
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will start the OpenFlow communication module
 *           in Soft Switch. This module builds the connection and
 *           communication between the Soft Switch and the Controller,
 *           which is runing on the other PC as a server.
 ***********************************************************************/
static uint32_t pofsc_init(void){
    /* Set OpenFlow connection attributes. */
    (void)pofsc_set_conn_attr(pofsc_controller_ip_addr, \
                              pofsc_controller_port, \
                              pofsc_conn_max_retry, \
                              pofsc_conn_retry_interval);

    /* Init the message queue for storing messages to be sent to controller. */
	pofbf_message_queue_init();

    /* Create connection and state machine task. */
	pofsc_main_task_ptr = kthread_run(pofsc_main_task, NULL, "POF_MAIN_TASKD");  
	if (IS_ERR(pofsc_main_task_ptr)){  
        printk(KERN_DEBUG "[POF_DEBUG_INFO] Create openflow main task, fail and return!\n");
        POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_TASK_CREATE_FAIL);
    }
    printk(KERN_DEBUG "[POF_DEBUG_INFO] >>Startup openflow task!\n");

    /* Create one task for sending  message to controller asynchronously. */
	pofsc_send_task_ptr = kthread_run(pofsc_send_msg_task, NULL, "POF_SEND_MSG_TASKD");  
	if (IS_ERR(pofsc_send_task_ptr)){  
        printk(KERN_DEBUG "[POF_DEBUG_INFO] Create openflow main task, fail and return!\n");
        POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_TASK_CREATE_FAIL);
    }
    printk(KERN_DEBUG "[POF_DEBUG_INFO] >>Startup task for sending message!\n");

    /* Create task to detect the ports. */
	pofsc_detectport_task_ptr = kthread_run(poflr_port_detect_task, NULL, "POF_PORT_DET_TASKD");  
	if (IS_ERR(pofsc_detectport_task_ptr)){  
        printk(KERN_DEBUG "[POF_DEBUG_INFO] Create port detect task, fail and return!\n");
        POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_TASK_CREATE_FAIL);
    }
    printk(KERN_DEBUG "[POF_DEBUG_INFO] >>Startup task for detecting ports!\n");

    /* Create one timer for sending echo message. */
	pofsc_start_timer();
    printk(KERN_DEBUG "[POF_DEBUG_INFO] >>Startup sending echo timer!\n");

    return POF_OK;
}



/***********************************************************************
 * The quit function
 * Form:     void terminate_handler(void)
 * Input:    NONE
 * Output:   NONE
 * Return:   VOID
 * Discribe: This function, which will reclaim all of the resource and
 *           terminate all of the task, is called when an unexpected crush
 *           happens, or we want to shut down the Soft Switch.
 ***********************************************************************/
uint32_t pofsc_terminate_flag = FALSE;
void terminate_handler(void){
    if(pofsc_terminate_flag == TRUE){
        return;
    }
    pofsc_terminate_flag = TRUE;
    printk(KERN_DEBUG "[POF_DEBUG_INFO] Call terminate_handler!");
    pofsc_destroy();
	/* TODO exit current thread? */
    do_exit(0);
}

/***********************************************************************
 * TODO
 * Destroy task, timer and queue.
 * Form:     uint32_t pofsc_destroy(void)
 * Input:    NONE
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function destroys all of the tasks, timers and queues
 *           in Soft Switch in order to reclaim the resource.
 ***********************************************************************/
static uint32_t pofsc_destroy(void){
    /* Free task,timer and queue. */
	if (!IS_ERR(pofsc_main_task_ptr)){
		kthread_stop(pofsc_main_task_ptr);
		printk(KERN_DEBUG "[POF_DEBUG_INFO] Kthread_stop main taskd!\n");
    }

	if (!IS_ERR(pofsc_send_task_ptr)){
		kthread_stop(pofsc_send_task_ptr);
		printk(KERN_DEBUG "[POF_DEBUG_INFO] Kthread_stop send taskd!\n");
    }

	if (!IS_ERR(pofsc_detectport_task_ptr)){
		kthread_stop(pofsc_detectport_task_ptr);
		printk(KERN_DEBUG "[POF_DEBUG_INFO] Kthread_stop detectPort taskd!\n");
    }

	del_timer(&exp_timer);  
	printk(KERN_DEBUG "[POF_DEBUG_INFO] Del_timer!\n");


#ifdef POF_DATAPATH_ON
	pof_datapath_destroy();
#endif

    return POF_OK;
}

/***********************************************************************
 * Set connection atributes.
 * Form:     uint32_t pofsc_set_conn_attr(const char *controller_ip, \
 *                                        uint16_t port, \
 *                                        uint32_t retry_max, \
 *                                        uint32_t retry_interval)
 * Input:    controller IP address, port, retry max, retry interval
 * Output:   pofsc_conn_desc
 * Return:   POF_OK or ERROR code
 * Discribe: This function sets connection atributes and stores it in
 *           pofsc_conn_desc.
 ***********************************************************************/
static uint32_t pofsc_set_conn_attr(const char *controller_ip, \
                                    uint16_t port, \
                                    uint32_t retry_max, \
                                    uint32_t retry_interval)
{
    memset((void *)&pofsc_conn_desc, 0, sizeof(pofsc_dev_conn_desc));

    memcpy((void*)pofsc_conn_desc.controller_ip, (void*)controller_ip, strlen(controller_ip));
    pofsc_conn_desc.controller_port = port;
    pofsc_conn_desc.conn_retry_max = retry_max;
    pofsc_conn_desc.conn_retry_interval = retry_interval;
    pofsc_conn_desc.conn_status.echo_interval = pofsc_echo_interval;

    return POF_OK;
}

/* Set the Controller's IP address. */
static uint32_t pofsc_set_controller_ip(char *ip_str){
	strncpy(pofsc_controller_ip_addr, ip_str, POF_IP_ADDRESS_STRING_LEN);
	return POF_OK;
}

/* Set the Controller's port. */
static uint32_t pofsc_set_controller_port(uint16_t port){
	pofsc_controller_port = port;
	return POF_OK;
}

/***********************************************************************
 * The task function for connection and state machine task.
 * Form:     int pofsc_main_task(void *arg_ptr)
 * Input:    NONE
 * Output:   NONE
 * Return:   VOID
 * Discribe: This task function keeps running the state machine of Soft
 *           Switch. The Soft Switch always works on one of states.
 *           Before the POFCS_CHANNEL_RUN state, this function
 *           builds the connection with the Cntroller by sending and
 *           receiving the "Hello" packet, replying the requests from the
 *           Controller, and so on. During the POFCS_CHANNEL_RUN state,
 *           it receive OpenFlow messages from the Controller and send
 *           them to the other modules to handle.
 ***********************************************************************/
static int pofsc_main_task(void *arg_ptr){
    pofsc_dev_conn_desc *conn_desc_ptr = (pofsc_dev_conn_desc *)&pofsc_conn_desc;
	/* Defined in pof_global.h-->. */
    pof_header          *head_ptr, head;
    int total_len = 0, tmp_len, left_len, rcv_len = 0, process_len = 0, packet_len = 0;
    struct socket *sock = NULL;
    int ret;

    /* Clear error record. */
    pofsc_protocol_error.type = 0xffff;

    /* State machine of the control module in Soft Switch. */
    while(1)
    {
		/* Exit thread. */
		if(kthread_should_stop()){
			printk(KERN_DEBUG "[POF_DEBUG_INFO] pofsc_main_task going to exit!\n");
			break;
		}

		/* Macro defined in pof_connection.h-->. */
        if(conn_desc_ptr->conn_status.state != POFCS_CHANNEL_RUN && !conn_desc_ptr->conn_retry_count){
            printk(KERN_DEBUG "[POF_DEBUG_INFO]>>Openflow Channel State: %s", pofsc_state_str[conn_desc_ptr->conn_status.state]);
        }

        switch(conn_desc_ptr->conn_status.state){
            case POFCS_CHANNEL_INVALID:

                /* Create openflow channel socket. */
                ret = pofsc_create_socket(&sock);
                if(ret == POF_OK){
                    conn_desc_ptr->sock = sock;
                    conn_desc_ptr->conn_status.state = POFCS_CHANNEL_CONNECTING;
                }else{
					break;
                    //terminate_handler();
                }
                break;

            case POFCS_CHANNEL_CONNECTING:
                /* Connect controller. */
				if(!conn_desc_ptr->conn_retry_count){
					printk(KERN_DEBUG "[POF_DEBUG_INFO] >>Connecting to POFController...\n");
				}

				/* Can't release socket in pofsc_connect if error happen, socket is create in this layer, just release in this layer, to avoid duplicate releasing! */
                ret = pofsc_connect(conn_desc_ptr->sock, conn_desc_ptr->controller_ip, conn_desc_ptr->controller_port);
                if(ret == POF_OK){
                    printk(KERN_DEBUG "[POF_DEBUG_INFO] >>Connect to controler SUC! %s: %u\n", \
                                        pofsc_controller_ip_addr, POF_CONTROLLER_PORT_NUM);
                    conn_desc_ptr->conn_status.state = POFCS_CHANNEL_CONNECTED;
					conn_desc_ptr->conn_retry_count = 0;
                }else{
					if(!conn_desc_ptr->conn_retry_count){
						printk(KERN_DEBUG "[POF_DEBUG_INFO] >>Connect to controler FAIL!\n");
					}
                    /* Delay several seconds. */
                    pofbf_task_delay(conn_desc_ptr->conn_retry_interval * 1000);
                    conn_desc_ptr->conn_retry_count++;
                    conn_desc_ptr->conn_status.last_error = (uint8_t)(POF_CONNECT_SERVER_FAILURE); 
                    //conn_desc_ptr->sock = NULL;
					sock_release(conn_desc_ptr->sock);
                    conn_desc_ptr->conn_status.state = POFCS_CHANNEL_INVALID;
                }
                break;

            case POFCS_CHANNEL_CONNECTED:
                /* Send hello to controller. Hello message has no body. */
				/* POFT_HELLO defined in pof_global.h-->. */
                pofsc_build_header(&head, \
                                   POFT_HELLO, \
                                   sizeof(pof_header), \
                                   g_upward_xid++);
                /* send hello message. */
                ret = pofsc_send(conn_desc_ptr->sock, (char*)&head, sizeof(pof_header));
                if(ret == POF_OK){
                    conn_desc_ptr->conn_status.state = POFCS_HELLO;
                }else{
                    printk(KERN_DEBUG "[POF_DEBUG_INFO] Send HELLO FAIL!\n");
					sock_release(conn_desc_ptr->sock);
                }

                break;

            case POFCS_HELLO:
                /* Receive hello from controller. */
                total_len = 0;
                left_len = 0;
                rcv_len = 0;
                process_len = 0;

                ret = pofsc_recv(conn_desc_ptr->sock, conn_desc_ptr->recv_buf , POF_RECV_BUF_MAX_SIZE, &total_len);
                if(ret == POF_OK){
                    printk(KERN_DEBUG "[POF_DEBUG_INFO] >>Recevie HELLO packet SUC!\n");
					poflr_clear_resource();
                    conn_desc_ptr->conn_status.state = POFCS_REQUEST_FEATURE;
                }else{
                    printk(KERN_DEBUG "[POF_DEBUG_INFO]Recv HELLO packet FAIL!\n");
					sock_release(conn_desc_ptr->sock);
                    break;
                }
                rcv_len += total_len;

                /* Parse. */
                head_ptr = (pof_header *)conn_desc_ptr->recv_buf;
                while(total_len < POF_NTOHS(head_ptr->length)){
                    ret = pofsc_recv(conn_desc_ptr->sock, conn_desc_ptr->recv_buf  + rcv_len, POF_RECV_BUF_MAX_SIZE -rcv_len,  &tmp_len);
                    if(ret != POF_OK){
                        printk(KERN_DEBUG "[POF_DEBUG_INFO] Recv HELLO FAIL, state reset to POFCS_CHANNEL_INVALID!\n");
						sock_release(conn_desc_ptr->sock);
                        break;
                    }

                    total_len += tmp_len;
                    rcv_len += tmp_len;
                }

                if(conn_desc_ptr->conn_status.state == POFCS_CHANNEL_INVALID){
                    break;
                }

                /* Check any error. */
                if(head_ptr->version > POF_VERSION){
                    printk(KERN_DEBUG "[POF_DEBUG_INFO] Version of recv-packet is higher than support!\n");
					/* POFHFC_INCOMPATIBLE defined in pof_global.h-->. */
                    pofsc_set_error(POFET_HELLO_FAILED, POFHFC_INCOMPATIBLE);
					sock_release(conn_desc_ptr->sock);
                    conn_desc_ptr->conn_status.state = POFCS_CHANNEL_INVALID;
                }else if(head_ptr->type != POFT_HELLO){
                    printk(KERN_DEBUG "[POF_DEBUG_INFO] Type of recv-packet is not HELLO, which we want to recv!\n");
                    pofsc_set_error(POFET_BAD_REQUEST, POFBRC_BAD_TYPE);
					sock_release(conn_desc_ptr->sock);
                    conn_desc_ptr->conn_status.state = POFCS_CHANNEL_INVALID;
                }

                process_len += POF_NTOHS(head_ptr->length);
                left_len = rcv_len - process_len;
                if(left_len == 0){
                    rcv_len = 0;
                    process_len = 0;
                }
                break;

            case POFCS_REQUEST_FEATURE:
                /* Wait to receive feature request from controller. */
                head_ptr = (pof_header *)(conn_desc_ptr->recv_buf  + process_len);
                if(!((left_len >= sizeof(pof_header))&&(left_len >= POF_NTOHS(head_ptr->length)))){
                    ret = pofsc_recv(conn_desc_ptr->sock, (conn_desc_ptr->recv_buf  + rcv_len), POF_RECV_BUF_MAX_SIZE - rcv_len, &total_len);
                    if(ret == POF_OK){
                        conn_desc_ptr->conn_status.state = POFCS_SET_CONFIG;
                    }else{
                        printk(KERN_DEBUG "[POF_DEBUG_INFO] Feature request FAIL!\n");
						sock_release(conn_desc_ptr->sock);
                        break;
                    }

                    rcv_len += total_len;
                    total_len += left_len;

                    head_ptr = (pof_header *)(conn_desc_ptr->recv_buf + process_len);
                    while(total_len < POF_NTOHS(head_ptr->length)){
                        ret = pofsc_recv(conn_desc_ptr->sock, ((conn_desc_ptr->recv_buf  + rcv_len)), POF_RECV_BUF_MAX_SIZE-rcv_len ,&tmp_len);
                        if(ret != POF_OK){
                            printk(KERN_DEBUG "[POF_DEBUG_INFO] Feature request FAIL!\n");
							sock_release(conn_desc_ptr->sock);
                            break;
                        }
                        total_len += tmp_len;
                        rcv_len += tmp_len;
                    }
                }

                if(conn_desc_ptr->conn_status.state == POFCS_CHANNEL_INVALID){
                    break;
                }

                head_ptr = (pof_header *)(conn_desc_ptr->recv_buf  + process_len);

                /* Check any error. */
                if(head_ptr->type != POFT_FEATURES_REQUEST){
					/* POFBRC_BAD_TYPE defined in pof_global.h-->. */
                    pofsc_set_error(POFET_BAD_REQUEST, POFBRC_BAD_TYPE);
                    sock_release(conn_desc_ptr->sock);
                    conn_desc_ptr->conn_status.state = POFCS_CHANNEL_INVALID;
                    break;
                }

                printk(KERN_DEBUG "[POF_DEBUG_INFO] >>Recevie FEATURE_REQUEST packet SUC!\n");
                conn_desc_ptr->conn_status.state = POFCS_SET_CONFIG;
                packet_len = POF_NTOHS(head_ptr->length);

				/* Parse message from controller */
                ret = pof_parse_msg_from_controller(conn_desc_ptr->recv_buf + process_len);

                if(ret != POF_OK){
                    printk(KERN_DEBUG "[POF_DEBUG_INFO] Features request FAIL!\n");
                    //terminate_handler();
                    sock_release(conn_desc_ptr->sock);
                    conn_desc_ptr->conn_status.state = POFCS_CHANNEL_INVALID;
                    break;
                }

                process_len += packet_len;
                left_len = rcv_len - process_len;
                if(left_len == 0){
                    rcv_len = 0;
                    process_len = 0;
                }

                break;

            case POFCS_SET_CONFIG:
                /* Receive set_config message from controller. */
                head_ptr = (pof_header *)(conn_desc_ptr->recv_buf  + process_len);
                if(!((left_len >= sizeof(pof_header))&&(left_len >= POF_NTOHS(head_ptr->length)))){
                    ret = pofsc_recv(conn_desc_ptr->sock, (conn_desc_ptr->recv_buf  + rcv_len), POF_RECV_BUF_MAX_SIZE - rcv_len, &total_len);
                    if(ret == POF_OK){
                        conn_desc_ptr->conn_status.state = POFCS_REQUEST_GET_CONFIG;
                    }else{
                        printk(KERN_DEBUG "[POF_DEBUG_INFO] Set config FAIL!\n");
						sock_release(conn_desc_ptr->sock);
                        break;
                    }

                    rcv_len += total_len;
                    total_len += left_len;

                    head_ptr = (pof_header *)(conn_desc_ptr->recv_buf + process_len);
                    while(total_len < POF_NTOHS(head_ptr->length)){
                        ret = pofsc_recv(conn_desc_ptr->sock, ((conn_desc_ptr->recv_buf  + rcv_len)), POF_RECV_BUF_MAX_SIZE-rcv_len ,&tmp_len);
                        if(ret != POF_OK){
                            printk(KERN_DEBUG "[POF_DEBUG_INFO ]Set config FAIL!\n");
							sock_release(conn_desc_ptr->sock);
                            break;
                        }
                        total_len += tmp_len;
                        rcv_len += tmp_len;
                    }
                }

                if(conn_desc_ptr->conn_status.state == POFCS_CHANNEL_INVALID){
                    break;
                }

                head_ptr = (pof_header *)(conn_desc_ptr->recv_buf  + process_len);

                /* Check any error. */
                if(head_ptr->version > POF_VERSION){
                    printk(KERN_DEBUG "[POF_DEBUG_INFO] Version of recv-packet is higher than support!\n");
                    pofsc_set_error(POFET_BAD_REQUEST, POFHFC_INCOMPATIBLE);
                    printk(KERN_DEBUG "[POF_DEBUG_INFO] Set config FAIL!\n");
					sock_release(conn_desc_ptr->sock);
                    conn_desc_ptr->conn_status.state = POFCS_CHANNEL_INVALID;
                    break;
                }else if(head_ptr->type != POFT_SET_CONFIG){
                    printk(KERN_DEBUG "[POF_DEBUG_INFO] Type of recv-packet is not SET_CONFIG, which we want to recv!\n");
                    pofsc_set_error(POFET_BAD_REQUEST, POFBRC_BAD_TYPE);
                    printk(KERN_DEBUG "[POF_DEBUG_INFO] Set config FAIL!\n");
					sock_release(conn_desc_ptr->sock);
                    conn_desc_ptr->conn_status.state = POFCS_CHANNEL_INVALID;
                    break;
                }

                printk(KERN_DEBUG "[POF_DEBUG_INFO] >>Recevie SET_CONFIG packet SUC!\n");
                conn_desc_ptr->conn_status.state = POFCS_REQUEST_GET_CONFIG;
                packet_len = POF_NTOHS(head_ptr->length);

				/* Parse message from controller */
                ret = pof_parse_msg_from_controller(conn_desc_ptr->recv_buf + process_len);

                if(ret != POF_OK){
                    printk(KERN_DEBUG "[POF_DEBUG_INFO] Set config FAIL!\n");
                    sock_release(conn_desc_ptr->sock);
                    conn_desc_ptr->conn_status.state = POFCS_CHANNEL_INVALID;
                    //terminate_handler();
                    break;
                }

                process_len += packet_len;
                left_len = rcv_len - process_len;

                if(left_len == 0){
                    rcv_len = 0;
                    process_len = 0;
                }
                break;

            case POFCS_REQUEST_GET_CONFIG:
                /* Wait to receive feature request from controller. */
                head_ptr = (pof_header *)(conn_desc_ptr->recv_buf  + process_len);
                if(!((left_len >= sizeof(pof_header)) && (left_len >= POF_NTOHS(head_ptr->length)))){
                    ret = pofsc_recv(conn_desc_ptr->sock, (conn_desc_ptr->recv_buf  + rcv_len), POF_RECV_BUF_MAX_SIZE - rcv_len, &total_len);
                    if(ret == POF_OK){
                        conn_desc_ptr->conn_status.state = POFCS_CHANNEL_RUN;
                    }else{
                        printk(KERN_DEBUG "[POF_DEBUG_INFO] Get config FAIL!\n");
						sock_release(conn_desc_ptr->sock);
                        break;
                    }

                    rcv_len += total_len;
                    total_len += left_len;

                    head_ptr = (pof_header *)(conn_desc_ptr->recv_buf + process_len);
                    while(total_len < POF_NTOHS(head_ptr->length)){
                        ret = pofsc_recv(conn_desc_ptr->sock, ((conn_desc_ptr->recv_buf  + rcv_len)), POF_RECV_BUF_MAX_SIZE-rcv_len ,&tmp_len);
                        if(ret != POF_OK){
							printk(KERN_DEBUG "[POF_DEBUG_INFO] Get config FAIL!\n");
							sock_release(conn_desc_ptr->sock);
                            break;
                        }

                        total_len += tmp_len;
                        rcv_len += tmp_len;
                    }
                }

                if(conn_desc_ptr->conn_status.state == POFCS_CHANNEL_INVALID){
                    break;
                }

                head_ptr = (pof_header *)(conn_desc_ptr->recv_buf  + process_len);
                /* Check any error. */
                if(head_ptr->type != POFT_GET_CONFIG_REQUEST){
                    pofsc_set_error(POFET_BAD_REQUEST, POFBRC_BAD_TYPE);
					printk(KERN_DEBUG "[POF_DEBUG_INFO] Get config FAIL!\n");
					sock_release(conn_desc_ptr->sock);
                    conn_desc_ptr->conn_status.state = POFCS_CHANNEL_INVALID;
                    break;
                }

                printk(KERN_DEBUG "[POF_DEBUG_INFO] >>Recevie GET_CONFIG_REQUEST packet SUC!\n");
                packet_len = POF_NTOHS(head_ptr->length);

				/* Parse message from controller */
                ret = pof_parse_msg_from_controller(conn_desc_ptr->recv_buf + process_len);
                if(ret != POF_OK){
					printk(KERN_DEBUG "[POF_DEBUG_INFO] Get config FAIL!\n");
					sock_release(conn_desc_ptr->sock);
                    conn_desc_ptr->conn_status.state = POFCS_CHANNEL_INVALID;
                    //terminate_handler();
                    break;
                }

                process_len += packet_len;
                left_len = rcv_len - process_len;

                if(left_len == 0){
                    rcv_len = 0;
                    process_len = 0;
                }

				/* Sleep 1sec. */
				pofbf_task_delay(1000);
                conn_desc_ptr->conn_status.state = POFCS_CHANNEL_RUN;
				printk(KERN_DEBUG "[POF_DEBUG_INFO] >>Connect to POFController successfully!\n");

                break;

            case POFCS_CHANNEL_RUN:
                /* Wait to receive feature request from controller. */
                head_ptr = (pof_header *)(conn_desc_ptr->recv_buf  + process_len);
                if(!((left_len >= sizeof(pof_header))&&(left_len >= POF_NTOHS(head_ptr->length)))){
                    /* Resv_buf has no space, so should move the left data to the head of the buf. */
                    if(POF_RECV_BUF_MAX_SIZE == rcv_len){
                        memcpy(conn_desc_ptr->recv_buf,  conn_desc_ptr->recv_buf  + process_len, left_len);
                        rcv_len = left_len;
                        process_len = 0;
                    }
                    ret = pofsc_recv(conn_desc_ptr->sock, (conn_desc_ptr->recv_buf  + rcv_len), POF_RECV_BUF_MAX_SIZE - rcv_len, &total_len);
                    if(ret != POF_OK){
						sock_release(conn_desc_ptr->sock);
                        break;
                    }

                    rcv_len += total_len;
                    total_len += left_len;

                    head_ptr = (pof_header *)(conn_desc_ptr->recv_buf + process_len);
                    while(total_len < POF_NTOHS(head_ptr->length)){
                        ret = pofsc_recv(conn_desc_ptr->sock, ((conn_desc_ptr->recv_buf  + rcv_len)), POF_RECV_BUF_MAX_SIZE-rcv_len ,&tmp_len);
                        if(ret != POF_OK){
							printk(KERN_DEBUG "[POF_DEBUG_INFO] POFCS_CHANNEL_RUN recv FAIL!\n");
							sock_release(conn_desc_ptr->sock);
							conn_desc_ptr->conn_status.state = POFCS_CHANNEL_INVALID;
                            break;
                        }
                    total_len += tmp_len;
                    rcv_len += tmp_len;
                    }
                }

                if(conn_desc_ptr->conn_status.state == POFCS_CHANNEL_INVALID){
                    break;
                }

                head_ptr = (pof_header *)(conn_desc_ptr->recv_buf  + process_len);
                packet_len = POF_NTOHS(head_ptr->length);
                /* Handle the message. Echo messages will be processed here and other messages will be forwarded to LUP. */
                ret = pofsc_run_process(conn_desc_ptr->recv_buf + process_len, packet_len);

                process_len += packet_len;
                left_len = rcv_len - process_len;

                if(left_len == 0){
                    rcv_len = 0;
                    process_len = 0;
                }
                break;

            default:
                conn_desc_ptr->conn_status.last_error = (uint8_t)POF_WRONG_CHANNEL_STATE;
                break;
        }

        /* If any error is detected, reply to controller immediately. */
        if(pofsc_protocol_error.type != 0xffff){
            tmp_len = 0;
            /* Build error message. */
            (void)pofsc_build_error_msg(conn_desc_ptr->send_buf, (uint16_t*)&tmp_len);

            /* Write error message in queue for sending. */
            ret = pofbf_message_queue_write(conn_desc_ptr->send_buf, (uint32_t)tmp_len);
            POF_CHECK_RETVALUE_TERMINATE(ret);
        }
    }
    return POF_OK;
}

/***********************************************************************
 * OpenFlow communication module task for sending message asynchronously.
 * Form:     int pofsc_send_msg_task(void *arg_ptr)
 * Input:    NONE
 * Output:   NONE
 * Return:   VOID
 * Discribe: Any message is first sent into messaage queue, and the task
 *           always check the message queue for sending. The messages
 *           include two types:
 *           1. Reply to controllers' request.
 *           2. Asynchrous message.
 *           The two types messages are built and sent to queue by two
 *           different tasks.
 ***********************************************************************/
static int pofsc_send_msg_task(void *arg_ptr){
    pofsc_dev_conn_desc *conn_desc_ptr = (pofsc_dev_conn_desc *)&pofsc_conn_desc;
    pof_header *head_ptr;
    int   ret;

    /* Polling the message queue. If valid, fetch one message and send it to controller. */
    while(1){
		/* Exit thread. */
		if(kthread_should_stop()){
			printk(KERN_DEBUG "[POF_DEBUG_INFO] pofsc_send_msg_task going to exit!\n");
			break;
		}

        switch(conn_desc_ptr->conn_status.state){
            case POFCS_CHANNEL_INVALID:
            case POFCS_CHANNEL_CONNECTING:
            case POFCS_CHANNEL_CONNECTED:
            case POFCS_HELLO:
                pofbf_task_delay(100);
                break;
            case POFCS_SET_CONFIG:
            case POFCS_REQUEST_FEATURE:
            case POFCS_REQUEST_GET_CONFIG:
            case POFCS_CHANNEL_RUN:
                /* Fetch one message from message queue. */
                ret = pofbf_message_queue_read(conn_desc_ptr->msg_buf, POF_QUEUE_MESSAGE_LEN);
                if(ret != POF_OK){
                    pofsc_set_error(POFET_SOFTWARE_FAILED, ret);
                    break;
                }

                /* Send message to server. */
                head_ptr = (pof_header*)conn_desc_ptr->msg_buf;
                ret = pofsc_send(conn_desc_ptr->sock, conn_desc_ptr->msg_buf, POF_HTONS(head_ptr->length));
                if(ret != POF_OK){
                    /* Return to invalid state. */
                    conn_desc_ptr->conn_status.last_error = (uint8_t)ret;
					sock_release(conn_desc_ptr->sock);
                    conn_desc_ptr->conn_status.state = POFCS_CHANNEL_INVALID;

                    /* Put the message back to queue for sendding next time. */
                    ret = pofbf_message_queue_write(conn_desc_ptr->msg_buf, POF_HTONS(head_ptr->length));
                    if(ret != POF_OK){
                        pofsc_set_error(POFET_SOFTWARE_FAILED, ret);
                        break;
                    }
                }
                break;
            default:
                conn_desc_ptr->conn_status.last_error = (uint8_t)POF_WRONG_CHANNEL_STATE;
                break;
        }
    }
    return POF_OK;
}


/* Sending echo message every 5sec. */
static void pofsc_start_timer(void){
	init_timer_on_stack(&exp_timer);

	exp_timer.expires = jiffies + pofsc_echo_interval * HZ;
	exp_timer.data = 0;
	exp_timer.function = pofsc_echo_timer;

	add_timer(&exp_timer);
}


/***********************************************************************
 * OpenFlow echo timer routine.
 * Form:     static void pofsc_echo_timer(uint32_t timer_id, int arg)
 * Input:    NONE
 * Output:   NONE
 * Return:   VOID
 * Discribe: The routine is only used to send echo request and not wait
 *           for echo reply.Echo reply is received and processed by main
 *           task.
 ***********************************************************************/
static void pofsc_echo_timer(uint32_t timer_id, int arg){
    pofsc_dev_conn_desc *conn_desc_ptr = (pofsc_dev_conn_desc *)&pofsc_conn_desc;
    pof_header head;
    uint16_t len;
    uint32_t ret;

	/* If valid, fetch one message and send it to controller. */
	switch(conn_desc_ptr->conn_status.state){
		case POFCS_CHANNEL_INVALID:
		case POFCS_CHANNEL_CONNECTING:
		case POFCS_CHANNEL_CONNECTED:
		case POFCS_HELLO:
		case POFCS_REQUEST_FEATURE:
			break;
		case POFCS_CHANNEL_RUN:
			/* Send echo to controller. */
			/* Build echo message. */
			len = sizeof(pof_header);
			pofsc_build_header(&head, POFT_ECHO_REQUEST, len, g_upward_xid++);

			/* Write error message into queue for sending. */
			ret = pofbf_message_queue_write((char*)&head, len);
			if(ret != POF_OK){
				pofsc_set_error(POFET_SOFTWARE_FAILED, ret);
			}
			break;
		default:
			break;
	}
	ret = mod_timer(&exp_timer, jiffies + pofsc_echo_interval * HZ);
	if(ret){
		printk(KERN_INFO "[POF_DEBUG_INFO] ERROR in mod_timer\n");
		return;
	}
	printk(KERN_INFO "[POF_DEBUG_INFO] SUCC in mod_timer\n");
    return;
}

/***********************************************************************
 * Create socket.
 * Form:     uint32_t pofsc_create_socket(struct socket **sock_ptr)
 * Input:    NONE
 * Output:   sock_ptr
 * Return:   POF_OK or ERROR code
 * Discribe: This function create the OpenFlow client socket with TCP
 *           channel.
 ***********************************************************************/
static uint32_t pofsc_create_socket(struct socket **sock_ptr){
	if(NULL==sock_ptr){
		return POF_ERROR;
	}
	if(sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, sock_ptr)){
		printk(KERN_DEBUG "[POF_DEBUG_INFO] socket create failed!\n");
        return (POF_CREATE_SOCKET_FAILURE);
	}
	printk(KERN_DEBUG "[POF_DEBUG_INFO] socket create SUCC!\n");
	return POF_OK;
}

/***********************************************************************
 * Connect controller.
 * Form:     uint32_t pofsc_connect(struct socket *sock, char *server_ip, uint16_t port)
 * Input:    sock, server IP string, port
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function connect the Soft Switch with the Conteroller
 *           by using the sock
 ***********************************************************************/
static uint32_t pofsc_connect(struct socket *sock, char *server_ip, uint16_t port){
	struct sockaddr_in*   dest = {0};
	struct inet_sock*     inet = NULL;
	__u8 *addr;
	char localIP[POF_IP_ADDRESS_STRING_LEN] = "\0";
	/* Defined in pof_global.h--> */
	uint8_t hwaddr[POF_ETH_ALEN];
	uint8_t port_id;
	int retVal = POF_OK;

	dest = (struct sockaddr_in*)kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
	if (!dest) {
		//sock_release(sock);
        return POF_CONNECT_SERVER_FAILURE;
	}

	dest->sin_family = AF_INET;
	dest->sin_addr.s_addr = in_aton(server_ip);
	dest->sin_port = htons(port);

	retVal = sock->ops->connect(sock, (struct sockaddr*)dest, sizeof(struct sockaddr_in), !O_NONBLOCK);
	if (retVal < 0) {
		//sock_release(sock);
        return POF_CONNECT_SERVER_FAILURE;
	}

	/* Connect success, get local IPv4 */
	inet = inet_sk(sock->sk);
	addr=(char *)&(inet->saddr);
	sprintf(localIP, "%u.%u.%u.%u", (__u32)addr[0],(__u32)addr[1],(__u32)addr[2],(__u32)addr[3]);

	/* Get hwaddr by ipaddr */
	if(poflr_get_hwaddr_by_ipaddr(hwaddr, localIP, &port_id) != POF_OK){
		//sock_release(sock);
		printk(KERN_DEBUG "[POF_DEBUG_INFO] Get the hwaddr of local port connecting to the Contrller fail!\n");
		return POF_ERROR;
	}

	/* Get the device id using the low 32bit of hardware address of local
	 * port connecting to the Controller. 
	 */
	/* Defined in pof_local_resource.h-->. */
	memcpy(&g_poflr_dev_id, hwaddr+2, POF_ETH_ALEN-2);
	POF_NTOHL_FUNC(g_poflr_dev_id);

	printk(KERN_DEBUG "[POF_DEBUG_INFO] Local physical port ip is %s\n", localIP);

	return POF_OK;
}

/***********************************************************************
 * Build the OpenFlow header.
 * Form:     void pofsc_build_header(pof_header *header, \
                                     uint8_t type, \
                                     uint16_t len, \
                                     uint32_t xid)
 * Input:    OpenFlow packet type, packet length, packet xid
 * Output:   header
 * Return:   VOID
 * Discribe: This function builds the OpenFlow header.
 ***********************************************************************/
static uint32_t pofsc_build_header(pof_header *header, \
                                   uint8_t type, \
                                   uint16_t len, \
                                   uint32_t xid)
{
	/* POF_VERSION defined in pof_global.h--> */
    header->version = POF_VERSION;
    header->type = type;
    header->length = len;
    header->xid = xid;
	/* Declare in pof_byte_transfer.h--> */
	pof_HtoN_transfer_header(header);

    return POF_OK;
}

/***********************************************************************
 * Send message.
 * Form:     uint32_t pofsc_send(struct socket *sock, char* buf, int len)
 * Input:    socket, data buffer, data length
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function send messages to the Controller in send task.
 ***********************************************************************/
static uint32_t pofsc_send(struct socket *sock, char* buf, int len){
	struct msghdr msg;
	struct iovec iov;
	mm_segment_t oldfs;
	int size = 0;

	if (sock->sk==NULL)
		return 0;

	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_flags = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	size = sock_sendmsg(sock,&msg,len);
	set_fs(oldfs);

	/* Send fail. */
    if (size == -1){
        printk(KERN_DEBUG "[POF_DEBUG_INFO] Socket write ERROR!\n");
		/* Must release this sock. state will be set to POFCS_CHANNEL_INVALID again. */
		//sock_release(sock);
        pofsc_performance_after_ctrl_disconn();
        return (POF_SEND_MSG_FAILURE);
    }

    return (POF_OK);
}

/* What to do after controller disconnect */
static uint32_t pofsc_performance_after_ctrl_disconn(void){
#if (POF_PERFORM_AFTER_CTRL_DISCONN == POF_AFTER_CTRL_DISCONN_SHUT_DOWN)
    terminate_handler();
#elif (POF_PERFORM_AFTER_CTRL_DISCONN == POF_AFTER_CTRL_DISCONN_RECONN)
    pofsc_conn_desc.conn_status.state = POFCS_CHANNEL_INVALID;
#endif // POF_PERFORM_AFTER_CTRL_DISCONN
    return POF_OK;
}


/***********************************************************************
 * Receive message.
 * Form:     uint32_t pofsc_recv(struct socket* sock, char* buf, int buflen, int* plen)
 * Input:    sock, the max length of the buffer
 * Output:   data buffer, data length
 * Return:   POF_OK or ERROR code
 * Discribe: This function receive the messages from the Controller.
 ***********************************************************************/
static uint32_t pofsc_recv(struct socket* sock, char* buf, int buflen, int* plen){
	struct msghdr msg;
	struct iovec iov;
	mm_segment_t oldfs;
	int size = 0;

	if (sock->sk==NULL){ 
		return POF_ERROR;
	}

	iov.iov_base = buf;
	iov.iov_len = buflen;

	msg.msg_flags = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	size = sock_recvmsg(sock,&msg,buflen,msg.msg_flags);
	set_fs(oldfs);

    if (size <= 0){
        printk(KERN_DEBUG "[POF_DEBUG_INFO] closed socket fd!\n");
		/* Must release this sock. state will be set to POFCS_CHANNEL_INVALID again */
		//sock_release(sock);
        pofsc_performance_after_ctrl_disconn();
        return (POF_RECEIVE_MSG_FAILURE);
    }
    *plen = size;

    return POF_OK;
}

/***********************************************************************
 * Set error.
 * Form:     void pofsc_set_error(uint16_t type, uint16_t code)
 * Input:    error type, error code
 * Output:   pofsc_protocol_error
 * Return:   VOID
 * Discribe: This function sets error which occurs in control module in
 *           the Soft Switch.
 ***********************************************************************/
static uint32_t pofsc_set_error(uint16_t type, uint16_t code){
    pofsc_protocol_error.type = POF_HTONS(type);
    pofsc_protocol_error.code = POF_HTONS(code);
	/* POF_FE_ID defined in pof_global.h-->. */
    pofsc_protocol_error.device_id = POF_HTONL(POF_FE_ID);
    return POF_OK;
}


/* Send packet upward to the Contrller through OpenFlow channel. */
uint32_t pofsc_send_packet_upward(uint8_t *packet, uint32_t len){
    if(POF_OK != pofbf_message_queue_write(packet, len)){
		/* Defined in pof_global.h--> */
        POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_WRITE_MSG_QUEUE_FAILURE);
    }

	return POF_OK;
}

/***********************************************************************
 * The process function during the POFCS_CHANNEL_RUN state.
 * Form:     uint32_t pofsc_run_process(char *message, uint16_t len)
 * Input:    message, length
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will be called when the communication module
 *           receive a message from the Controller during the
 *           POFCS_CHANNEL_RUN state.
 ***********************************************************************/
static uint32_t pofsc_run_process(char *message, uint16_t len){
    uint32_t ret = POF_OK;
    pof_header *head_ptr;
    pofsc_dev_conn_desc *conn_desc_ptr = (pofsc_dev_conn_desc *)&pofsc_conn_desc;

    head_ptr = (pof_header *)message;
    if(POF_NTOHS(head_ptr->length)!= len){
        pofsc_set_error(POFET_BAD_REQUEST, POFBRC_BAD_LEN);
        return POF_OK;
    }

    /* Handle echo reply message. */
    if(head_ptr->type == POFT_ECHO_REPLY){
        /* Record last echo time. */
		struct timeval tmval;
		do_gettimeofday(&tmval);	
        conn_desc_ptr->last_echo_time = tmval.tv_sec; 
    }else{
        /* Forward to LPU board through IPC channel. */
        ret = pof_parse_msg_from_controller(message);
		POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);
    }

    return POF_OK;
}

/***********************************************************************
 * Build error message and send it to message queue.
 * Form:     uint32_t pofsc_build_error_msg(char *message, uint16_t *len_p)
 * Input:    message data, message length
 * Output:   message data
 * Return:   VOID
 * Discribe: This function build error message and send it to message
 *           queue.
 ***********************************************************************/
static uint32_t pofsc_build_error_msg(char *message, uint16_t *len_p){
    pof_header *head_ptr = (pof_header*)message;
    uint32_t ret = POF_OK;
    uint16_t len = sizeof(pof_header) + sizeof(pof_error);

    /* Build header. */
     pofsc_build_header(head_ptr, POFT_ERROR, len, g_upward_xid++);

    /* Copy error content into message. */
    memcpy((message + sizeof(pof_header)), &pofsc_protocol_error, sizeof(pof_error));

    /* Clear error record. */
    pofsc_protocol_error.type = 0xFFFF;

    *len_p = len;
    return ret;
}




module_init(pofswitch_init);
module_exit(pofswitch_exit);

MODULE_AUTHOR("Lu shiliang");
MODULE_LICENSE("GPL"); 


