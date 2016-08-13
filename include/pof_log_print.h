#ifndef _POF_LOG_PRINT_H_
#define _POF_LOG_PRINT_H_

#include <linux/kernel.h>

#define POF_DEBUG_PRINTK() \
	printk(KERN_DEBUG "[POF_DEBUG_INFO:] type = %s(%d), code = %s(0x%.4x)", g_pofec_error.type_str, \
	g_pofec_error.type, g_pofec_error.error_str, g_pofec_error.code)



#endif // _POF_LOG_PRINT_H_
