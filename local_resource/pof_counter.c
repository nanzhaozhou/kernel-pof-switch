#include <linux/slab.h>

#include "../include/pof_local_resource.h"
#include "../include/pof_global.h"
#include "../include/pof_connection.h"
#include "../include/pof_log_print.h"
#include "../include/pof_byte_transfer.h"


/* The number of counter. */
static uint32_t poflr_counter_number = POFLR_COUNTER_NUMBER;

/* Counter table. */
/* Defined in pof_local_resource.h-->. */
static poflr_counters *poflr_counter;




/* Set counter number. */
uint32_t poflr_set_counter_number(uint32_t counter_num_arg){
	poflr_counter_number = counter_num_arg;
	return POF_OK;
}

/* Get counter number. */
uint32_t poflr_get_counter_number(uint32_t *counter_number_ptr){
	*counter_number_ptr = poflr_counter_number;
	return POF_OK;
}


/* Free counter resource. */
uint32_t poflr_free_counter(void){
	if(NULL != poflr_counter){
		kfree(poflr_counter->counter);
		kfree(poflr_counter->state);
		kfree(poflr_counter);
	}

	return POF_OK;
}

/* Initialize counter resource. */
uint32_t poflr_init_counter(void){

    /* Initialize counter table. */
    poflr_counter = (poflr_counters *)kmalloc(sizeof(poflr_counters), GFP_KERNEL);
	if(poflr_counter == NULL){
		poflr_free_table_resource();
		POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_ALLOCATE_RESOURCE_FAILURE);
	}
    memset(poflr_counter, 0, sizeof(poflr_counters));

    poflr_counter->counter = (pof_counter *)kmalloc(sizeof(pof_counter) * poflr_counter_number, GFP_KERNEL);
	if(poflr_counter->counter == NULL){
		poflr_free_table_resource();
		POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_ALLOCATE_RESOURCE_FAILURE);
	}
    memset(poflr_counter->counter, 0, sizeof(pof_counter) * poflr_counter_number);

    poflr_counter->state = (uint32_t *)kmalloc(sizeof(uint32_t) * poflr_counter_number, GFP_KERNEL);
	if(poflr_counter->state == NULL){
		poflr_free_table_resource();
		POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_ALLOCATE_RESOURCE_FAILURE);
	}
    memset(poflr_counter->state, 0, sizeof(uint32_t) * poflr_counter_number);

	return POF_OK;
}

/* Empty counter. */
uint32_t poflr_empty_counter(void){
    memset(poflr_counter->counter, 0, sizeof(pof_counter) * poflr_counter_number);
    memset(poflr_counter->state, 0, sizeof(uint32_t) * poflr_counter_number);
    poflr_counter->counter_num = 0;
	
	return POF_OK;
}

/***********************************************************************
 * Initialize the counter corresponding the counter_id.
 * Form:     uint32_t poflr_counter_init(uint32_t counter_id)
 * Input:    counter id
 * Output:   NONE
 * Return:   POF_OK or Error code
 * Discribe: This function will initialize the counter corresponding the
 *           counter_id. The initial counter value is zero.
 ***********************************************************************/
uint32_t poflr_counter_init(uint32_t counter_id){
    pof_counter *p;

	if(!counter_id){
		//printk(KERN_DEBUG "[POF_DEBUG_INFO:] The counter_id 0 means that counter is no need.\n");
		return POF_OK;
	}

    /* Check counter id. */
    if(counter_id >= poflr_counter_number){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_COUNTER_MOD_FAILED, POFCMFC_BAD_COUNTER_ID, g_recv_xid);
    }
    if(poflr_counter->state[counter_id] == POFLR_STATE_INVALID){
        poflr_counter->state[counter_id] = POFLR_STATE_VALID;
        poflr_counter->counter_num++;
        p = &poflr_counter->counter[counter_id];
        p->counter_id = counter_id;
        p->value = 0;
    }

    //printk(KERN_DEBUG "[POF_DEBUG_INFO:] The counter[%u] has been initialized!\n", counter_id);
    return POF_OK;
}

/***********************************************************************
 * Delete the counter corresponding the counter_id.
 * Form:     uint32_t poflr_counter_delete(uint32_t counter_id)
 * Input:    counter id
 * Output:   NONE
 * Return:   POF_OK or Error code
 * Discribe: This function will delete the counter.
 ***********************************************************************/
uint32_t poflr_counter_delete(uint32_t counter_id){
    pof_counter *p;

    if(!counter_id){
        return POF_OK;
    }

    /* Check counter id. */
    if(counter_id >= poflr_counter_number){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_COUNTER_MOD_FAILED, POFCMFC_BAD_COUNTER_ID, g_recv_xid);
    }
    if(poflr_counter->state[counter_id] == POFLR_STATE_INVALID){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_COUNTER_MOD_FAILED, POFCMFC_COUNTER_UNEXIST, g_recv_xid);
    }

    poflr_counter->state[counter_id] = POFLR_STATE_INVALID;
    poflr_counter->counter_num--;
    p = &poflr_counter->counter[counter_id];
    p->counter_id = 0;
    p->value = 0;

    printk(KERN_DEBUG "[POF_DEBUG_INFO:] The counter[%u] has been deleted!\n", counter_id);
    return POF_OK;
}

/***********************************************************************
 * Cleare counter value.
 * Form:     uint32_t poflr_counter_clear(uint32_t counter_id)
 * Input:    device id, counter id
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will make the counter value corresponding to
 *           counter_id to be zero.
 ***********************************************************************/
uint32_t poflr_counter_clear(uint32_t counter_id){
    if(!counter_id){
        return POF_OK;
    }

    /* Check counter_id. */
    if(counter_id >= poflr_counter_number){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_COUNTER_MOD_FAILED, POFCMFC_BAD_COUNTER_ID, g_recv_xid);
    }
    if(poflr_counter->state[counter_id] == POFLR_STATE_INVALID){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_COUNTER_MOD_FAILED, POFCMFC_COUNTER_UNEXIST, g_recv_xid);
    }

    /* Initialize the counter value. */
    pof_counter * tmp_counter_ptr = & (poflr_counter->counter[counter_id]);
    tmp_counter_ptr->value = 0;

    printk(KERN_DEBUG "[POF_DEBUG_INFO:] Clear counter value SUC!\n");
    return POF_OK;
}

/***********************************************************************
 * Get counter value.
 * Form:     uint32_t poflr_get_counter_value(uint32_t counter_id)
 * Input:    device id, counter id
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will get the counter value corresponding to
 *           tht counter_id and send it to the Controller as reply
 *           through the OpenFlow channel.
 ***********************************************************************/
uint32_t poflr_get_counter_value(uint32_t counter_id){
    pof_counter counter = {0};

    /* Check counter_id. */
    if(!counter_id || counter_id >= poflr_counter_number){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_COUNTER_MOD_FAILED, POFCMFC_BAD_COUNTER_ID, g_recv_xid);
    }
    if(counter_id && poflr_counter->state[counter_id] != POFLR_STATE_VALID){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_COUNTER_MOD_FAILED, POFCMFC_COUNTER_UNEXIST, g_recv_xid);
    }

    counter.command = POFCC_REQUEST;
    counter.counter_id = counter_id;
    counter.value = (poflr_counter->counter[counter_id]).value;
    pof_NtoH_transfer_counter(&counter);

	/* Delay 0.1s. */
	pofbf_task_delay(100);

    if(POF_OK != pofec_reply_msg(POFT_COUNTER_REPLY, g_recv_xid, sizeof(pof_counter), (uint8_t *)&counter)){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_SOFTWARE_FAILED, POF_WRITE_MSG_QUEUE_FAILURE, g_recv_xid);
    }

    printk(KERN_DEBUG "[POF_DEBUG_INFO:] Get counter value SUC! counter id = %u, counter value = %llu", \
                        counter_id, counter.value);
    return POF_OK;
}

/***********************************************************************
 * Increace the counter
 * Form:     uint32_t poflr_counter_increace(uint32_t counter_id)
 * Input:    counter_id
 * Output:   NONE
 * Return:   POF_OK or Error code
 * Discribe: This function increase the counter value corresponding to
 *           the counter_id by one.
 ***********************************************************************/
uint32_t poflr_counter_increace(uint32_t counter_id){
    pof_counter *p;

    if(!counter_id){
        return POF_OK;
    }

    /* Check the counter id. */
    if(counter_id >= poflr_counter_number){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_COUNTER_MOD_FAILED, POFCMFC_BAD_COUNTER_ID, g_upward_xid++);
    }
    if(poflr_counter->state[counter_id] == POFLR_STATE_INVALID){
		poflr_counter_init(counter_id);
    }

    p = &poflr_counter->counter[counter_id];
    p->value++;

    return POF_OK;
}





