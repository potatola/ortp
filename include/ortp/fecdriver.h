#ifndef ms2_fec_driver
#define ms2_fec_driver

#include <ortp/port.h>
#include <ortp/str_utils.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fec object
**/
typedef struct _RtpSession RtpSession;
typedef struct _MSFecDriverDesc MSFecDriverDesc;
typedef struct _MSFecDriver MSFecDriver;

struct _MSFecDriverDesc{
    bool_t (*outgoing_rtp)(MSFecDriver *obj, mblk_t *rtp);
    bool_t (*incoming_rtp)(MSFecDriver *obj, mblk_t *rtp, uint32_t user_ts);
    bool_t (*process_rtcp)(MSFecDriver *obj, mblk_t *rtcp);
    bool_t (*flush)(MSFecDriver *obj);
    bool_t (*set_rate)(MSFecDriver *obj, uint16_t block_size, uint16_t source_num);
    void (*uinit)(MSFecDriver *obj);
};

struct _MSFecDriver{
    MSFecDriverDesc *desc;
	RtpSession *session;
	int format;
};

ORTP_PUBLIC bool_t ms_fec_driver_outgoing_rtp(MSFecDriver *obj, mblk_t *rtp);
ORTP_PUBLIC bool_t ms_fec_driver_incoming_rtp(MSFecDriver *obj, mblk_t *rtp, uint32_t user_ts);
ORTP_PUBLIC bool_t ms_fec_driver_process_rtcp(MSFecDriver *obj, mblk_t *rtcp);
ORTP_PUBLIC bool_t ms_fec_driver_set_rate(MSFecDriver *obj, uint16_t block_size, uint16_t source_num);
ORTP_PUBLIC bool_t ms_fec_driver_flush(MSFecDriver *obj);
ORTP_PUBLIC void ms_fec_driver_destroy(MSFecDriver *obj);

/**
 * my fec object
**/
ORTP_PUBLIC MSFecDriver * ms_simple_fec_driver_new(RtpSession *session, int format);


#ifdef __cplusplus
}
#endif

#endif

