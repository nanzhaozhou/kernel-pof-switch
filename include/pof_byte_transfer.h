#ifndef _POF_BYTETRANSFER_H_
#define _POF_BYTETRANSFER_H_

#include "pof_common.h"

/* Define some byte order transfer operators. */
#if( POF_BYTE_ORDER == POF_BIG_ENDIAN )

#define POF_NTOH64(x)                  (x)
#define POF_HTON64(x)                  (x)
#define POF_NTOHL(x)                   (x)
#define POF_HTONL(x)                   (x)
#define POF_NTOHS(x)                   (x)
#define POF_HTONS(x)                   (x)

#else /* POF_BYTE_ORDER == POF_LITTLE_ENDIAN */

#define POF_NTOH64(x)                  ((((x) & 0x00000000000000ffLL) << 56) | \
                                        (((x) & 0x000000000000ff00LL) << 40) | \
                                        (((x) & 0x0000000000ff0000LL) << 24) | \
                                        (((x) & 0x00000000ff000000LL) <<  8) | \
                                        (((x) & 0x000000ff00000000LL) >>  8) | \
                                        (((x) & 0x0000ff0000000000LL) >> 24) | \
                                        (((x) & 0x00ff000000000000LL) >> 40) | \
                                        (((x) & 0xff00000000000000LL) >> 56))

#define POF_HTON64(x)                  ((((x) & 0x00000000000000ffLL) << 56) | \
                                        (((x) & 0x000000000000ff00LL) << 40) | \
                                        (((x) & 0x0000000000ff0000LL) << 24) | \
                                        (((x) & 0x00000000ff000000LL) <<  8) | \
                                        (((x) & 0x000000ff00000000LL) >>  8) | \
                                        (((x) & 0x0000ff0000000000LL) >> 24) | \
                                        (((x) & 0x00ff000000000000LL) >> 40) | \
                                        (((x) & 0xff00000000000000LL) >> 56))

#define POF_NTOHL(x)                   ((((x) & 0x000000ff) << 24) | \
                                        (((x) & 0x0000ff00) <<  8) | \
                                        (((x) & 0x00ff0000) >>  8) | \
                                        (((x) & 0xff000000) >> 24))

#define POF_HTONL(x)                   ((((x) & 0x000000ff) << 24) | \
                                        (((x) & 0x0000ff00) <<  8) | \
                                        (((x) & 0x00ff0000) >>  8) | \
                                        (((x) & 0xff000000) >> 24))

#define POF_NTOHS(x)                   ((((x) & 0x00ff) << 8) | \
                                        (((x) & 0xff00) >> 8))

#define POF_HTONS(x)                   ((((x) & 0x00ff) << 8) | \
                                        (((x) & 0xff00) >> 8))
#endif /* POF_BYTE_ORDER */

/* Define some byte order transfer equation. */
#define POF_NTOH64_FUNC(x) ((x) = POF_NTOH64(x))
#define POF_HTON64_FUNC(x) ((x) = POF_HTON64(x))
#define POF_NTOHL_FUNC(x) ((x) = POF_NTOHL(x))
#define POF_HTONL_FUNC(x) ((x) = POF_HTONL(x))
#define POF_NTOHS_FUNC(x) ((x) = POF_NTOHS(x))
#define POF_HTONS_FUNC(x) ((x) = POF_HTONS(x))

/* Define some byte order transfer function. */
extern uint32_t pof_HtoN_transfer_header(void * ptr);
extern uint32_t pof_NtoH_transfer_header(void * ptr);
extern uint32_t pof_HtoN_transfer_switch_config(void * ptr);
extern uint32_t pof_HtoN_transfer_flow_table_resource(void *ptr);
extern uint32_t pof_HtoN_transfer_port_status(void *ptr);
extern uint32_t pof_NtoH_transfer_port(void * ptr);
extern uint32_t pof_HtoN_transfer_switch_features(void *ptr);
extern uint32_t pof_NtoH_transfer_flow_table(void *ptr);
extern uint32_t pof_NtoH_transfer_flow_entry(void *ptr);
extern uint32_t pof_NtoH_transfer_meter(void *ptr);
extern uint32_t pof_NtoH_transfer_group(void *ptr);
extern uint32_t pof_NtoH_transfer_counter(void *ptr);
extern uint32_t pof_HtoN_transfer_packet_in(void *ptr);
extern uint32_t pof_NtoH_transfer_error(void *ptr);




#endif // _POF_BYTETRANSFER_H_
