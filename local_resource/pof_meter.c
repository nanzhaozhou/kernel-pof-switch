#include <linux/slab.h>
#include <linux/string.h>

#include "../include/pof_local_resource.h"
#include "../include/pof_global.h"
#include "../include/pof_connection.h"
#include "../include/pof_log_print.h"
#include "../include/pof_byte_transfer.h"


/* The number of meter. */
static uint32_t poflr_meter_number = POFLR_METER_NUMBER;

/* Meter table. */
static poflr_meters *poflr_meter;


/* Set meter number. */
uint32_t poflr_set_meter_number(uint32_t meter_num_arg){
	poflr_meter_number = meter_num_arg;
	return POF_OK;
}

/* Get meter number. */
uint32_t poflr_get_meter_number(uint32_t *meter_number_ptr){
	*meter_number_ptr = poflr_meter_number;
	return POF_OK;
}


/* Free meter resource. */
uint32_t poflr_free_meter(void){
	if(NULL != poflr_meter){
		kfree(poflr_meter->meter);
		kfree(poflr_meter->state);
		kfree(poflr_meter);
	}

	return POF_OK;
}

/* Initialize meter resource. */
uint32_t poflr_init_meter(void){

    /* Initialize meter table. */
	/* Defined in pof_local_resource.h-->. */
    poflr_meter = (poflr_meters *)kmalloc(sizeof(poflr_meters), GFP_KERNEL);
	if(poflr_meter == NULL){
		poflr_free_table_resource();
		POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_ALLOCATE_RESOURCE_FAILURE);
	}
    memset(poflr_meter, 0, sizeof(poflr_meters));

    poflr_meter->meter = (pof_meter *)kmalloc(sizeof(pof_meter) * poflr_meter_number, GFP_KERNEL);
	if(poflr_meter->meter == NULL){
		poflr_free_table_resource();
		POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_ALLOCATE_RESOURCE_FAILURE);
	}
    memset(poflr_meter->meter, 0, sizeof(pof_meter) * poflr_meter_number);

    poflr_meter->state = (uint32_t *)kmalloc(sizeof(uint32_t) * poflr_meter_number, GFP_KERNEL);
	if(poflr_meter->state == NULL){
		poflr_free_table_resource();
		POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_ALLOCATE_RESOURCE_FAILURE);
	}
    memset(poflr_meter->state, 0, sizeof(uint32_t) * poflr_meter_number);

	return POF_OK;
}

/* Empty meter. */
uint32_t poflr_empty_meter(void){
    memset(poflr_meter->meter, 0, sizeof(pof_meter) * poflr_meter_number);
    memset(poflr_meter->state, 0, sizeof(uint32_t) * poflr_meter_number);
    poflr_meter->meter_num = 0;

	return POF_OK;
}

/* Get meter table. */
uint32_t poflr_get_meter(poflr_meters **meter_ptrptr){
	*meter_ptrptr = poflr_meter;
	return POF_OK;
}

/***********************************************************************
 * Add the meter.
 * Form:     uint32_t poflr_mod_meter_entry(uint32_t meter_id, uint32_t rate)
 * Input:    device id, meter id, rate
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will add the meter in the meter table.
 ***********************************************************************/
uint32_t poflr_add_meter_entry(uint32_t meter_id, uint32_t rate){
    pof_meter *meter;

    /* Check meter_id. */
    if(meter_id >= poflr_meter_number){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_METER_MOD_FAILED, POFMMFC_INVALID_METER, g_recv_xid);
    }

    if(poflr_meter->state[meter_id] == POFLR_STATE_VALID){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_METER_MOD_FAILED, POFMMFC_METER_EXISTS, g_recv_xid);
    }

    meter = &(poflr_meter->meter[meter_id]);
    meter->meter_id = meter_id;
    meter->rate = rate;

    poflr_meter->meter_num++;
    poflr_meter->state[meter_id] = POFLR_STATE_VALID;

    printk(KERN_DEBUG "[POF_DEBUG_INFO] Add meter SUC!\n");
    return POF_OK;
}

/***********************************************************************
 * Modify the meter.
 * Form:     uint32_t poflr_mod_meter_entry(uint32_t meter_id, uint32_t rate)
 * Input:    device id, meter id, rate
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will modify the meter in the meter table.
 ***********************************************************************/
uint32_t poflr_modify_meter_entry(uint32_t meter_id, uint32_t rate){
    pof_meter *meter;

    /* Check meter_id. */
    if(meter_id >= poflr_meter_number){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_METER_MOD_FAILED, POFMMFC_INVALID_METER, g_recv_xid);
    }

    if(poflr_meter->state[meter_id] == POFLR_STATE_INVALID){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_METER_MOD_FAILED, POFMMFC_UNKNOWN_METER, g_recv_xid);
    }

    meter = &(poflr_meter->meter[meter_id]);
    meter->meter_id = meter_id;
    meter->rate = rate;

    printk(KERN_DEBUG "[POF_DEBUG_INFO] Modify meter SUC!\n");
    return POF_OK;
}

/***********************************************************************
 * Delete the meter.
 * Form:     uint32_t poflr_mod_meter_entry(uint32_t meter_id, uint32_t rate)
 * Input:    device id, meter id, rate
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will add the meter in the meter table.
 ***********************************************************************/
uint32_t poflr_delete_meter_entry(uint32_t meter_id, uint32_t rate){
    pof_meter *meter;

    /* Check meter_id. */
    if(meter_id >= poflr_meter_number){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_METER_MOD_FAILED, POFMMFC_INVALID_METER, g_recv_xid);
    }
    if(poflr_meter->state[meter_id] == POFLR_STATE_INVALID){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_METER_MOD_FAILED, POFMMFC_UNKNOWN_METER, g_recv_xid);
    }

    meter = &(poflr_meter->meter[meter_id]);
    meter->meter_id = 0;
    meter->rate = 0;

    poflr_meter->meter_num--;
    poflr_meter->state[meter_id] = POFLR_STATE_INVALID;

    printk(KERN_DEBUG "[POF_DEBUG_INFO] Delete meter SUC!\n");
    return POF_OK;
}

