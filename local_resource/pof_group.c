#include <linux/slab.h>

#include "../include/pof_local_resource.h"
#include "../include/pof_global.h"
#include "../include/pof_connection.h"
#include "../include/pof_log_print.h"

/* The number of group. */
static uint32_t poflr_group_number = POFLR_GROUP_NUMBER;

/* Group table. */
/* Defined in pof_local_resource.h--> */
static poflr_groups *poflr_group;




/* Set group number. */
uint32_t poflr_set_group_number(uint32_t group_num_arg){
	poflr_group_number = group_num_arg;
	return POF_OK;
}

/* Get group number. */
uint32_t poflr_get_group_number(uint32_t *group_number_ptr){
	*group_number_ptr = poflr_group_number;
	return POF_OK;
}


/* Free group resource. */
uint32_t poflr_free_group(void){
	if(NULL != poflr_group){
		kfree(poflr_group->group);
		kfree(poflr_group->state);
		kfree(poflr_group);
	}

	return POF_OK;
}

/* Initialize group resource. */
uint32_t poflr_init_group(void){

    /* Initialize group table. */
    poflr_group = (poflr_groups *)kmalloc(sizeof(poflr_groups), GFP_KERNEL);
	if(poflr_group == NULL){
		poflr_free_table_resource();
		POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_ALLOCATE_RESOURCE_FAILURE);
	}
    memset(poflr_group, 0, sizeof(poflr_groups));

    poflr_group->group = (pof_group *)kmalloc(sizeof(pof_group) * poflr_group_number, GFP_KERNEL);
	if(poflr_group->group == NULL){
		poflr_free_table_resource();
		POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_ALLOCATE_RESOURCE_FAILURE);
	}
    memset(poflr_group->group, 0, sizeof(pof_group)*poflr_group_number);

    poflr_group->state = (uint32_t *)kmalloc(sizeof(uint32_t) * poflr_group_number, GFP_KERNEL);
	if(poflr_group->state == NULL){
		poflr_free_table_resource();
		POF_ERROR_HANDLE_RETURN_NO_UPWARD(POFET_SOFTWARE_FAILED, POF_ALLOCATE_RESOURCE_FAILURE);
	}
    memset(poflr_group->state, 0, sizeof(uint32_t) * poflr_group_number);

	return POF_OK;
}

/* Empty group. */
uint32_t poflr_empty_group(void){
    memset(poflr_group->group, 0, sizeof(pof_group) * poflr_group_number);
    memset(poflr_group->state, 0, sizeof(uint32_t) * poflr_group_number);
    poflr_group->group_num = 0;

	return POF_OK;
}

/***********************************************************************
 * Add the group entry.
 * Form:     uint32_t poflr_add_group_entry(pof_group *group_ptr)
 * Input:    device id, group id, counter id, group type, action number,
 *           action data
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will add the group entry in the group table.
 ***********************************************************************/
uint32_t poflr_add_group_entry(pof_group *group_ptr){
    uint32_t ret;

    /* Check group_id. */
    if(group_ptr->group_id >= poflr_group_number){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_GROUP_MOD_FAILED, POFGMFC_INVALID_GROUP, g_recv_xid);
    }

    if(poflr_group->state[group_ptr->group_id] == POFLR_STATE_VALID){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_GROUP_MOD_FAILED, POFGMFC_GROUP_EXISTS, g_recv_xid);
    }

    /* Initialize the counter_id. */
    ret = poflr_counter_init(group_ptr->counter_id);
    POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

    memcpy(&poflr_group->group[group_ptr->group_id], group_ptr,  sizeof(pof_group));
    poflr_group->group_num ++;
    poflr_group->state[group_ptr->group_id] = POFLR_STATE_VALID;

    printk(KERN_DEBUG "[POF_DEBUG_INFO:] Add group entry SUC!\n");
    return POF_OK;
}

/***********************************************************************
 * Modify the group entry.
 * Form:     uint32_t poflr_modify_group_entry(pof_group *group_ptr)
 * Input:    device id, group id, counter id, group type, action number,
 *           action data
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will modify the group entry in the group table.
 ***********************************************************************/
uint32_t poflr_modify_group_entry(pof_group *group_ptr){

    /* Check group_id. */
    if(group_ptr->group_id >= poflr_group_number){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_GROUP_MOD_FAILED, POFGMFC_INVALID_GROUP, g_recv_xid);
    }
    if(poflr_group->state[group_ptr->group_id] == POFLR_STATE_INVALID){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_GROUP_MOD_FAILED, POFGMFC_UNKNOWN_GROUP, g_recv_xid);
    }

    /* Check the counter_id. */
    if(group_ptr->counter_id != poflr_group->group[group_ptr->group_id].counter_id){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_GROUP_MOD_FAILED, POFGMFC_BAD_COUNTER_ID, g_recv_xid);
    }

    memcpy(&poflr_group->group[group_ptr->group_id], group_ptr,  sizeof(pof_group));

    printk(KERN_DEBUG "[POF_DEBUG_INFO:] Modify group entry SUC!\n");
    return POF_OK;
}

/***********************************************************************
 * Delete the group entry.
 * Form:     uint32_t poflr_delete_group_entry(pof_group *group_ptr)
 * Input:    device id, group id, counter id, group type, action number,
 *           action data
 * Output:   NONE
 * Return:   POF_OK or ERROR code
 * Discribe: This function will delete the group entry in the group table.
 ***********************************************************************/
uint32_t poflr_delete_group_entry(pof_group *group_ptr){
    uint32_t ret;

    /* Check group_id. */
    if(group_ptr->group_id >= poflr_group_number){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_GROUP_MOD_FAILED, POFGMFC_INVALID_GROUP, g_recv_xid);
    }
    if(poflr_group->state[group_ptr->group_id] == POFLR_STATE_INVALID){
        POF_ERROR_HANDLE_RETURN_UPWARD(POFET_GROUP_MOD_FAILED, POFGMFC_UNKNOWN_GROUP, g_recv_xid);
    }

    /* Delete the counter_id. */
    ret = poflr_counter_delete(group_ptr->counter_id);
    POF_CHECK_RETVALUE_RETURN_NO_UPWARD(ret);

    poflr_group->group_num --;
    poflr_group->state[group_ptr->group_id] = POFLR_STATE_INVALID;
    memset(&poflr_group->group[group_ptr->group_id], 0, sizeof(pof_group));

    printk(KERN_DEBUG "[POF_DEBUG_INFO:] Delete group entry SUC!\n");
    return POF_OK;
}

/* Get group table. */
uint32_t poflr_get_group(poflr_groups **group_ptrptr){
	*group_ptrptr = poflr_group;
	return POF_OK;
}





