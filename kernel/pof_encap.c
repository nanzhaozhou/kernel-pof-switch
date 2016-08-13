#include <linux/string.h>

#include "../include/pof_global.h"
#include "../include/pof_byte_transfer.h"
#include "../include/pof_connection.h"
#include "../include/pof_log_print.h"
#include "../include/pof_common.h"
#include "../include/pof_local_resource.h"


/* Error messages. */
/* struct pofec_error defined in pof_local_resource.h-->. */
pofec_error g_pofec_error = {0};

/* Data buffer. */
/* Defined in pof_connection.h-->. */
char pofec_queue_msg_buf[POF_QUEUE_MESSAGE_LEN] = {0};


/*******************************************************************************
 * Set the error.
 * Form:     uint32_t pofec_set_error(uint16_t type, char *type_str, uint16_t code, char *error_str)
 * Input:    error type, error type string, error code, error string
 * Output:   NONE
 * Return:   POF_OK or Error code
 * Discribe: This function set the error in g_pofec_error.
*******************************************************************************/
uint32_t pofec_set_error(uint16_t type, char *type_str, uint16_t code, char *error_str){
    g_pofec_error.type = type;
    g_pofec_error.code = code;
    strcpy(g_pofec_error.type_str, type_str);
    strcpy(g_pofec_error.error_str, error_str);
    return POF_OK;
}


/*******************************************************************************
 * Send the error message to Controller.
 * Form:     uint32_t pofec_reply_error(uint16_t type, \
 *                                      uint16_t code, \
 *                                      char *s, \
 *                                      uint32_t xid)
 * Input:    error type, error code, error string
 * Output:   NONE
 * Return:   POF_OK or Error code
 * Discribe: This function encapsulats the error message, then send it to the
 *           Controller through the OpenFlow channel.
*******************************************************************************/
uint32_t pofec_reply_error(uint16_t type, uint16_t code, char *s, uint32_t xid){
    pof_error *error_ptr;

    /* Build the pof body. */
    error_ptr = (pof_error *)(pofec_queue_msg_buf + sizeof(pof_header));
    error_ptr->code = code;
    error_ptr->device_id = POF_FE_ID;
    error_ptr->type = type;
    memcpy(error_ptr->err_str, s, strlen(s)+1);

    pof_NtoH_transfer_error(pofec_queue_msg_buf + sizeof(pof_header));

    if(POF_OK != pofec_reply_msg(POFT_ERROR, xid, sizeof(pof_error), NULL)){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_SOFTWARE_FAILED, POF_WRITE_MSG_QUEUE_FAILURE, g_upward_xid++);
    }

    printk(KERN_DEBUG "[POF_DEBUG_INFO]pofec_reply_error DONE!\n");
    return POF_OK;
}


/*******************************************************************************
 * Send the message to Controller.
 * Form:     uint32_t  pofec_reply_msg(uint8_t type,
 *                                     uint32_t xid,
 *                                     uint32_t msg_len,
 *                                     uint8_t  *msg_body)
 * Input:    message type, xid, length of message, message data
 * Output:   NONE
 * Return:   POF_OK or Error code
 * Discribe: This function encapsulats the message, which the soft switch want
 *           to send to the Controller, to OpenFlow format. If msg_body is NULL,
 *           it means the message data has already written into the pofec_queue_msg_buf
 *           start on sizeof(pof_header).
*******************************************************************************/
uint32_t  pofec_reply_msg(uint8_t  type, \
                          uint32_t xid, \
                          uint32_t msg_len, \
                          uint8_t  *msg_body)
{
    pofsc_dev_conn_desc *conn_desc_ptr = (pofsc_dev_conn_desc *)&pofsc_conn_desc;
    pof_header* header_ptr;
    uint32_t total_len = msg_len + sizeof(pof_header);

    /* If valid, fetch one message and send it to controller. */
    switch(conn_desc_ptr->conn_status.state){
        case POFCS_CHANNEL_INVALID:
        case POFCS_CHANNEL_CONNECTING:
        case POFCS_CHANNEL_CONNECTED:
        case POFCS_HELLO:
            break;
        case POFCS_REQUEST_FEATURE:
		case POFCS_SET_CONFIG:
		case POFCS_REQUEST_GET_CONFIG:
        case POFCS_CHANNEL_RUN:

			header_ptr = (pof_header*)pofec_queue_msg_buf;
			header_ptr->version = POF_VERSION;
			header_ptr->type = type;
			header_ptr->xid = xid;
			header_ptr->length = total_len;

			pof_HtoN_transfer_header(header_ptr);

			if(msg_body != NULL){
				memcpy(pofec_queue_msg_buf + sizeof(pof_header), (uint8_t*)msg_body, msg_len);
			}

			/* Defined in pofswitch.c-->. */
			if(POF_OK != pofsc_send_packet_upward(pofec_queue_msg_buf, total_len)){
				/* Defined in pof_global.h-->. */
				POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_WRITE_MSG_QUEUE_FAILURE);
			}
            break;
        default:
            break;
    }

    return POF_OK;
}


