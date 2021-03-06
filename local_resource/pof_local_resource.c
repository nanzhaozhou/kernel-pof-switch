#include <linux/types.h> /* For uint32_t. */
#include <linux/kernel.h>
#include <linux/string.h>
#include "../include/pof_log_print.h"
#include "../include/pof_global.h"
#include "../include/pof_local_resource.h"
#include "../include/pof_byte_transfer.h"
#include "../include/pof_connection.h"


/* Description of device table resource. */
/* Defined in pof_global.h-->. */
/* Is not a pointer, no need to kmalloc. */
static pof_flow_table_resource poflr_table_resource_desc;

/* Device id, not static, will be initialized in pofsc_connect. */
uint32_t g_poflr_dev_id = 0;

/* Description of switch config. */
pof_switch_config poflr_switch_config;

/* Description of switch feature. */
pof_switch_features poflr_switch_feature;

/***********************************************************************
 * Initialize the table resource.
 * Form:     static uint32_t poflr_init_table_resource(void)
 * Input:    NONE
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will initialize the local table resource
 *           including the flow tables, group table, meter table and
 *           counter table.
 ***********************************************************************/
static uint32_t poflr_init_table_resource(void){
    pof_table_resource_desc *tbl_rsc_desc_ptr;
    uint32_t i, ret = POF_OK, table_size = 0;
	uint32_t counter_number = 0, group_number = 0, meter_number = 0;
	uint16_t *key_len_ptr = NULL;
	uint8_t  *table_number_ptr = NULL;

	ret = poflr_init_flow_table();
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	ret = poflr_init_group();
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	ret = poflr_init_meter();
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	ret = poflr_init_counter();
	POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

	poflr_get_table_number(&table_number_ptr);
	poflr_get_table_size(&table_size);
	poflr_get_key_len(&key_len_ptr);
	poflr_get_meter_number(&meter_number);
	poflr_get_counter_number(&counter_number);
	poflr_get_group_number(&group_number);

    /* Initialize table resource description of each type of table. */
    for(i = 0; i < POF_MAX_TABLE_TYPE; i++){
        tbl_rsc_desc_ptr = &(poflr_table_resource_desc.tbl_rsc_desc[i]);

        tbl_rsc_desc_ptr->device_id = POF_FE_ID;
        tbl_rsc_desc_ptr->type = i;
        tbl_rsc_desc_ptr->tbl_num = table_number_ptr[i];
        tbl_rsc_desc_ptr->key_len = key_len_ptr[i];
        tbl_rsc_desc_ptr->total_size = table_size;
    }
    poflr_table_resource_desc.counter_num = counter_number;
    poflr_table_resource_desc.meter_num = meter_number;
    poflr_table_resource_desc.group_num = group_number;

    return POF_OK;
}


/* Init port, counter, flow table, meter, group, description. */
uint32_t pof_localresource_init(void){
    uint32_t ret = POF_OK;

    /* Initialize the local physical port infomation. */
    ret = poflr_init_port();
    POF_CHECK_RETVALUE_TERMINATE(ret);

	/* Disable all port OpenFlow forwarding when start. */
    poflr_disable_all_port();

    /* Initialize the table configuration. */
    ret = poflr_init_table_resource();
    POF_CHECK_RETVALUE_TERMINATE(ret);

    return POF_OK;
}

uint32_t poflr_free_table_resource(void){
    /* Free the flow table resource. */
	poflr_free_flow_table();

    /* Free group resource. */
	poflr_free_group();

    /* Free meter resource. */
	poflr_free_meter();

    /* Free counter resource. */
	poflr_free_counter();

	return POF_OK;
}

/***********************************************************************
 * Empty the Soft Switch resource.
 * Form:     poflr_empty_resource(void)
 * Input:    NONE
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will empty the Soft Switch resource such as
 *           flow entry, flow table, group table, meter table, counter
 *           table.
 ***********************************************************************/
uint32_t poflr_clear_resource(void){
    poflr_disable_all_port();
	poflr_empty_flow_table();
	poflr_empty_group();
	poflr_empty_meter();
	poflr_empty_counter();

	printk(KERN_DEBUG "[POF_DEBUG_INFO:] Switch resource has been clear.\n");
    return POF_OK;
}

/***********************************************************************
 * Set the config of the switch
 * Form:     uint32_t poflr_set_config(uint16_t flags, \
 *                                     uint16_t miss_send_len)
 * Input:    flags, miss send length
 * Output:   NONE
 * Return:   POF_OK.
 * Discribe: This function will set the config of the switch.
 ***********************************************************************/
uint32_t poflr_set_config(uint16_t flags, uint16_t miss_send_len){
    poflr_switch_config.flags = flags;
    poflr_switch_config.miss_send_len = miss_send_len;

    return POF_OK;
}

/***********************************************************************
 * Reply the config REQUEST from Controller
 * Form:     uint32_t poflr_reply_config(void)
 * Input:    NONE
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will reply the config REQUEST from Controller
 *           through OpenFlow communication.
 ***********************************************************************/
uint32_t poflr_reply_config(void){
	pof_switch_config config = poflr_switch_config;
    pof_HtoN_transfer_switch_config(&config);

    if(POF_OK != pofec_reply_msg(POFT_GET_CONFIG_REPLY, g_recv_xid, sizeof(pof_switch_config), (uint8_t *)&config)){
		/* Defined in pof_global.h--> */
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_SOFTWARE_FAILED, POF_WRITE_MSG_QUEUE_FAILURE, g_recv_xid);
    }

    return POF_OK;
}

/***********************************************************************
 * Reply the table resource.
 * Form:     uint32_t  poflr_reply_table_resource()
 * Input:    NONE
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will reply the table resource to the Controller.
 ***********************************************************************/
uint32_t  poflr_reply_table_resource(void){
	pof_flow_table_resource flow_table_resource = poflr_table_resource_desc;
    pof_HtoN_transfer_flow_table_resource(&flow_table_resource);

    if(POF_OK != pofec_reply_msg(POFT_RESOURCE_REPORT, g_recv_xid, sizeof(pof_flow_table_resource), (uint8_t *)&flow_table_resource)){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_SOFTWARE_FAILED, POF_WRITE_MSG_QUEUE_FAILURE, g_recv_xid);
    }

    return POF_OK;
}

/***********************************************************************
 * Reply the port resource
 * Form:     uint32_t  poflr_reply_port_resource(void)
 * Input:    NONE
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will reply the port resource.
 ***********************************************************************/
uint32_t  poflr_reply_port_resource(void){
	/* Defined in pof_global.h--> */
    pof_port_status port_status = {0};
	pof_port *port_ptr = NULL;
    uint32_t i;
	uint16_t port_number = 0;

	poflr_get_port_number(&port_number);
	poflr_get_port(&port_ptr);

    for(i=0; i<port_number; i++){
        memcpy(&port_status.desc, (uint8_t *)((pof_port *)port_ptr+i), sizeof(pof_port));
        pof_HtoN_transfer_port_status(&port_status);

        if(POF_OK != pofec_reply_msg(POFT_PORT_STATUS, g_recv_xid, sizeof(pof_port_status), (uint8_t *)&port_status)){
            POF_ERROR_HANDLE_RETURN_UPWARD(POFET_SOFTWARE_FAILED, POF_WRITE_MSG_QUEUE_FAILURE, g_recv_xid);
        }
    }

    return POF_OK;
}

uint32_t poflr_reset_dev_id(void){
	pof_port *port_ptr = NULL;
    uint32_t i;
	uint16_t port_number = 0;

	poflr_get_port(&port_ptr);
	poflr_get_port_number(&port_number);

    for(i=0; i<port_number; i++){
        port_ptr[i].device_id = POF_FE_ID;
    }

    for(i=0; i<POF_MAX_TABLE_TYPE; i++){
        poflr_table_resource_desc.tbl_rsc_desc[i].device_id = POF_FE_ID;
    }

    return POF_OK;
}

/***********************************************************************
 * Reply the switch feature REQUEST from Controller.
 * Form:     uint32_t  poflr_reply_feature_resource(void)
 * Input:    NONE
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will initialize and reply the switch feature
 *           REQUEST from Controller. The switch feature will be stored
 *           in poflr_switch_feature.
 ***********************************************************************/
uint32_t  poflr_reply_feature_resource(void)
{
	/* Defined in pof_global.h--> */
    pof_switch_features feature = {0};
    char szVendorName[POF_NAME_MAX_LENGTH] = "huawei";
    char szfwid[POF_NAME_MAX_LENGTH] = "";
    char szlkupid[POF_NAME_MAX_LENGTH] = "";
	uint32_t i;
	uint16_t port_number = 0;
	uint8_t  *table_number_ptr = NULL;

	poflr_get_port_number(&port_number);
	poflr_get_table_number(&table_number_ptr);

    feature.dev_id = POF_FE_ID;
    feature.port_num = port_number;
    feature.table_num = 0;
	for(i=0; i<POF_MAX_TABLE_TYPE; i++){
		feature.table_num += table_number_ptr[i];
	}
	/* Macros defined in pof_global.h--> */
    feature.capabilities = POFC_FLOW_STATS | POFC_TABLE_STATS | POFC_PORT_STATS | POFC_GROUP_STATS;

	strncpy(szfwid,   POFSWITCH_VERSION, POF_NAME_MAX_LENGTH);
	strncpy(szlkupid, POFSWITCH_VERSION, POF_NAME_MAX_LENGTH);

    memcpy(feature.vendor_id, szVendorName, POF_NAME_MAX_LENGTH);
    memcpy(feature.dev_fw_id, szfwid, POF_NAME_MAX_LENGTH);
    memcpy(feature.dev_lkup_id, szlkupid, POF_NAME_MAX_LENGTH);

    memcpy(&poflr_switch_feature, &feature, sizeof(pof_switch_features));
	/* Defined in pof_byte_transfer.h--> */
    pof_HtoN_transfer_switch_features(&feature);

    if(POF_OK != pofec_reply_msg(POFT_FEATURES_REPLY, g_recv_xid, sizeof(pof_switch_features), (uint8_t *)&feature)){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_SOFTWARE_FAILED, POF_WRITE_MSG_QUEUE_FAILURE, g_recv_xid);
    }

    return POF_OK;
}





