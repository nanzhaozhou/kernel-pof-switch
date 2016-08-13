#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/delay.h>/* For msleep. */
#include <linux/wait.h>
#include <linux/sched.h>/* For TASK_INTERRUPTIBLE. */
#include "../include/pof_common.h"
#include "../include/pof_global.h"

/* Global message queue, but only directly access in this file scope. */
static pof_message_queue_t g_message_queue;
/* For blocking read. */
static wait_queue_head_t g_waitqueue;


/***********************************************************************
 * Init the message queue.
 * Form:     uint32_t pofbf_message_queue_init(void)
 * Input:    NONE
 * Output:   NONE
 * Return:   Always POF_OK
 * Discribe: This function inits the global message queue.
 ***********************************************************************/
uint32_t pofbf_message_queue_init(void){
	INIT_LIST_HEAD(&(g_message_queue.qhead));
	g_message_queue.splock = (spinlock_t *)kmalloc(sizeof(spinlock_t), GFP_KERNEL);
	spin_lock_init(g_message_queue.splock);
	//DECLARE_WAIT_QUEUE_HEAD(g_waitqueue);
	init_waitqueue_head(&g_waitqueue);
	return POF_OK;
}


/***********************************************************************
 * Read message from queue.
 * Form:     uint32_t pofbf_queue_read(
 *                                     char *buf, \
 *                                     uint32_t max_len, \
 *)
 * Input:    max len
 * Output:   data buffer
 * Return:   POF_OK or POF_ERROR
 * Discribe: This function reads message from the queue, if queue empty, it will block.
 ***********************************************************************/
uint32_t pofbf_message_queue_read(char *buf, uint32_t max_len){
	struct list_head *tmp=NULL; 
	pof_message_t *node_p=NULL;

	/* If queue empty, just block and wait. */
	while( list_empty(&(g_message_queue.qhead)) ){
		interruptible_sleep_on(&g_waitqueue);
	}
	/* Blocking return. */
	list_for_each(tmp, &(g_message_queue.qhead)){
		node_p = list_entry(tmp, struct pof_message_t, list);
		break;
	}
	if(node_p->len > max_len){
		return POF_ERROR;
	}
	// MAYBE USING MEMCPY!
	//strcpy(buf, node_p->buf);
	memcpy(buf, node_p->buf, node_p->len);
	/* Delete node. */
	list_del(&(node_p->list));
	/* Free memory */
	kfree(node_p);
	return POF_OK;
}


/***********************************************************************
 * Write message to queue.
 * Form:     uint32_t pofbf_message_queue_write(
 *                                      char *message, \
 *                                      uint32_t msg_len)
 * Input:    message data, message length
 * Output:   NONE
 * Return:   POF_OK or Error code
 * Discribe: This function writes the message data to the message queue
 ***********************************************************************/
uint32_t pofbf_message_queue_write(const char *message, uint32_t msg_len){
	pof_message_t *node_p=(pof_message_t *)kmalloc(sizeof(pof_message_t), GFP_ATOMIC);
	if( (NULL == node_p) || (msg_len > POF_MESSAGE_LEN_MAX) ){
		return POF_ERROR;
	}
	// MAYBE USING MEMCPY!
	//strcpy(node_p->buf, message);
	memcpy(node_p->buf, message, msg_len);
	node_p->len=msg_len;
	spin_lock(g_message_queue.splock);
	list_add_tail(&(node_p->list), &(g_message_queue.qhead));
	spin_unlock(g_message_queue.splock);
	/* Wake up the only thread reading from this queue. */
	wake_up_interruptible(&g_waitqueue);
	return POF_OK;
}

/***********************************************************************
 * Task delay.
 * Form:     uint32_t pofbf_task_delay(uint32_t delay)
 * Input:    delay time
 * Output:   NONE
 * Return:   VOID
 * Discribe: This function delays the task. The unit of the delay is
 *           milli-second.
 ***********************************************************************/
uint32_t pofbf_task_delay(uint32_t delay){
    msleep(delay);
    return POF_OK;
}

