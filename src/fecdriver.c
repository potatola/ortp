
#include "ortp/fecdriver.h"
#include "ortp/ortp.h"
#include "ortp/str_utils.h"
#include "ortp/cauchy_256.h"
#include <stdio.h>

#define FEC_DEBUG

// TODO: called in __rtp_session_sendm_with_ts, before transformed into network format. Should be dealed with.
bool_t ms_fec_driver_outgoing_rtp(MSFecDriver * obj,mblk_t * rtp){
	if(obj->desc->outgoing_rtp) {
		return obj->desc->outgoing_rtp(obj, rtp);
	}
	ortp_message("MSFecDriver: unimplemented outgoing_rtp() call");
	return FALSE;
}

bool_t ms_fec_driver_incoming_rtp(MSFecDriver * obj,mblk_t * rtp,uint32_t user_ts){
	if(obj->desc->incoming_rtp) {
		return obj->desc->incoming_rtp(obj, rtp, user_ts);
	}
	ortp_message("MSFecDriver: unimplemented incoming_rtp() call");
	return FALSE;
}

bool_t ms_fec_driver_process_rtcp(MSFecDriver * obj,mblk_t * rtcp){
	if(obj->desc->process_rtcp) {
		return obj->desc->process_rtcp(obj, rtcp);
	}
	ortp_message("MSFecDriver: unimplemented process_rtcp() call");
	return FALSE;
}

bool_t ms_fec_driver_set_rate(MSFecDriver *obj, uint16_t block_size, uint16_t source_num){
	if(obj->desc->set_rate) {
		return obj->desc->set_rate(obj, block_size, source_num);
	}
	ortp_message("MSFecDriver: unimplemented flush() call");
	return FALSE;
}

bool_t ms_fec_driver_flush(MSFecDriver * obj){
	if(obj->desc->flush) {
		return obj->desc->flush(obj);
	}
	ortp_message("MSFecDriver: unimplemented flush() call");
	return FALSE;
}

// TODO: not called yet
void ms_fec_driver_destroy(MSFecDriver * obj){
	if(obj->desc->uinit) {
		obj->desc->uinit(obj);
	}
	ortp_free(obj);
}

/**
 * simple fec driver
**/
FILE *log_file;

typedef struct _RtpSession RtpSession;
void rtp_session_send_rtcp_FEC(RtpSession *session, uint8_t subtype, uint16_t seq, uint16_t index, uint16_t block_size, uint16_t source_num, const uint8_t *data, int datalen);

typedef struct _MSSimpleFecDriver{
	MSFecDriver parent;
	unsigned char ** source_packets;
	char *redundancy;
	uint16_t block_max, block_size, source_num, source_curr, fec_rate;
	uint32_t last_ts;
	queue_t recv_fec;	//rtcp with fec data
}MSSimpleFecDriver;

// TODO: check for memory leakage
#define MSG_STORE_SIZE 1600
static unsigned char* msg2stream(mblk_t *im) {
	unsigned char *ret;
	int pkt_size;
	msgpullup(im, -1);
	pkt_size = msgdsize(im);
	ret = (unsigned char *)malloc(sizeof(int) + MSG_STORE_SIZE * sizeof(char));
	memset(ret, 0, sizeof(int) + MSG_STORE_SIZE * sizeof(char));
	memcpy(ret, &pkt_size, sizeof(int));
	memcpy(ret+sizeof(int), im->b_rptr, im->b_wptr - im->b_rptr);
	return ret;
}

/**
 * fec_rate: block_size in the original function. set to 0 to MUTE fec
**/
bool_t simple_fec_driver_set_rate(MSFecDriver *baseobj, uint16_t fec_rate, uint16_t source_num){
	MSSimpleFecDriver *obj = (MSSimpleFecDriver *)baseobj;
	return TRUE;
	if(source_num == 0) {
		int delta = (100 + obj->source_num - 1) / obj->source_num;
		if(fec_rate == 1 && obj->fec_rate <= 100) {
			obj->fec_rate += delta;
		}
		if(fec_rate == 0) {
			obj->fec_rate = obj->fec_rate > delta ? obj->fec_rate - delta : 0;
		}
	}
	else {
		obj->block_size = 0;
		obj->source_num = source_num;
		obj->fec_rate = fec_rate;
	}
	ortp_message("FecDriver: fec rate set to (%d, %d%%)", obj->source_num, obj->fec_rate);
#if defined(ANDROID)
	log_file = fopen("sdcard/test1.txt", "a+");
	fprintf(log_file, "FecDriver: fec rate set to (%d, %d%%)\n", obj->source_num, obj->fec_rate);
	fclose(log_file);
#endif
	return TRUE;
}

bool_t simple_fec_driver_outgoing_rtp(MSFecDriver * baseobj,mblk_t * rtp){
	MSSimpleFecDriver *obj = (MSSimpleFecDriver *)baseobj;

	uint16_t rtp_seq = ((rtp_header_t *)rtp->b_rptr)->seq_number;
	uint32_t rtp_ts = ((rtp_header_t *)rtp->b_rptr)->timestamp;
	rtp_header_t *header = (rtp_header_t *)rtp->b_rptr;
	int msg_size = msgdsize(rtp);
	
	//ortp_message("SimpleFecDriver: outgoing rtp, seq=%d, ts=%d", rtp_seq, rtp_ts);
	if(obj->fec_rate == 0) return TRUE;

	//an int indicating size of the packet is added at head of the stream
	if(obj->block_max < msg_size+sizeof(int)) obj->block_max = msg_size+sizeof(int);
	obj->source_packets[obj->source_curr] = msg2stream(rtp);

	//update stat
	obj->source_curr ++;
	
	//ortp_message("GYF: source cur=%d, num=%d, ts=%d, last_ts=%d", obj->source_curr, obj->source_num, rtp_ts, obj->last_ts);
	if(rtp_ts != obj->last_ts) {
		obj->last_ts = rtp_ts;

		if(obj->source_curr >= obj->source_num) {
			//try encode
			int fec_index = 0;
			char *redundancy;
			int redundancy_size = (obj->block_max + 7) / 8 * 8;
			int redundancy_num = (obj->source_curr*obj->fec_rate/100);
			ortp_message("RSEncoder: seq=%d, source_num=%d, redun_num=%d", rtp_seq+1-obj->source_curr, obj->source_curr, redundancy_num);
			if(redundancy_num == 0) return TRUE;
			free(obj->redundancy);
			obj->redundancy = (char *)malloc(redundancy_num * redundancy_size * sizeof(char));
			
			if (cauchy_256_encode(obj->source_curr, redundancy_num, (const unsigned char**)obj->source_packets, obj->redundancy, redundancy_size)) {
				ortp_message("RSEncoder: ENCODE ERROR!");
#if defined(ANDROID) && defined(FEC_DEBUG)
				log_file = fopen("sdcard/test1.txt", "a+");
				fprintf(log_file, "RSEncoder: ENCODE ERROR!\n");
				fclose(log_file);
#endif
				return FALSE;
			}

			//ortp_message("GYF: FEC encode succeed, seq=%d, size=%d", rtp_seq-obj->source_curr+1, redundancy_size);
			redundancy = obj->redundancy;
			for(; fec_index < redundancy_num; fec_index++) {
				rtp_session_send_rtcp_FEC(obj->parent.session, 0, rtp_seq+1-obj->source_curr, fec_index, 
					(uint16_t)(obj->source_curr+redundancy_num), (uint16_t)obj->source_curr, (uint8_t *)redundancy, redundancy_size);
				redundancy += redundancy_size;
			}
			
			obj->block_max = 0;
			for(fec_index=0; fec_index<obj->source_curr; fec_index++) {
				free(obj->source_packets[fec_index]);
			}
			obj->source_curr = 0;
		}
	}
	
	return TRUE;
}

mblk_t *reconstruct_rtp_packet(unsigned char *buffer, int pkt_size){
	mblk_t *mp = NULL;
	rtp_header_t *hdr;
	int i;

	mp=allocb(pkt_size,BPRI_MED);
	memcpy(mp->b_wptr,buffer,pkt_size);
	mp->b_wptr+=pkt_size;

	hdr = (rtp_header_t *)mp->b_rptr;
	hdr->ssrc = htonl (hdr->ssrc);
	hdr->timestamp = htonl (hdr->timestamp);
	hdr->seq_number = htons (hdr->seq_number);
	for (i = 0; i < hdr->cc; i++)
		hdr->csrc[i] = htonl (hdr->csrc[i]);
		
	return mp;
}

void rtp_session_rtp_parse(RtpSession *session, mblk_t *mp, uint32_t local_str_ts, struct sockaddr *addr, socklen_t addrlen);
bool_t simple_fec_driver_RS_decode(MSFecDriver * baseobj, queue_t *sources, int idx, int k, int n, uint32_t user_ts, uint16_t min_seq){
	MSSimpleFecDriver *obj = (MSSimpleFecDriver *)baseobj;
	Block *block_info = (Block *)malloc(k * sizeof(Block));
	int received_count = 0, received_source = 0, end_idx = idx+k;
	int packet_size = 0;

	mblk_t *rtp = peekq(sources);
	mblk_t *fec = peekq(&obj->recv_fec);
	uint16_t seq, fec_seq;
	int decidx;
	memset(block_info, 0, k * sizeof(Block));

	while(rtp != NULL && rtp != &sources->_q_stopper) {
		seq = ((rtp_header_t *)rtp->b_rptr)->seq_number;
		//ortp_message("GYF: seeing rtp seq=%d", seq);
		if(seq < idx) {
			rtp = rtp->b_next;
			continue;
		}
		if(seq >= end_idx) break;
		else {
			mblk_t *duprtp = dupmsg(rtp);
			block_info[received_count].data = msg2stream(duprtp);
			block_info[received_count].row = seq-idx;
			freemsg(duprtp);
			
			received_count ++;
			ortp_message("RSDecoder: source packet=%d, num=%d, row=%d", seq, received_count, seq-idx);
#if defined(ANDROID) && defined(FEC_DEBUG)
			log_file = fopen("sdcard/test1.txt", "a+");
			fprintf(log_file, "RSDecoder: source packet=%d, num=%d, row=%d\n", seq, received_count, seq-idx);
			fclose(log_file);
#endif
			if(received_count >= k) {
				for(decidx=0; decidx<received_count; decidx++) {
					free(block_info[decidx].data);
				}
				free(block_info);
				return TRUE;
			}
		}
		
		rtp = rtp->b_next;
	}

	received_source = received_count;

	while(fec != NULL && fec != &(obj->recv_fec._q_stopper)) {
		fec_seq = rtcp_FEC_get_seq(fec);
		if(fec_seq != idx) break;
		else {
			rtcp_FEC_get_data(fec,&(block_info[received_count].data),&packet_size);
			block_info[received_count].row = rtcp_FEC_get_source_num(fec)+rtcp_FEC_get_index(fec);
			
			received_count ++;
			ortp_message("RSDecoder: fec packet=(%d,%d), num=%d, row=%d", fec_seq, rtcp_FEC_get_index(fec), 
				received_count, block_info[received_count-1].row);
#if defined(ANDROID) && defined(FEC_DEBUG)
			log_file = fopen("sdcard/test1.txt", "a+");
			fprintf(log_file, "RSDecoder: fec packet=(%d,%d), num=%d, row=%d\n", fec_seq, rtcp_FEC_get_index(fec), 
				received_count, block_info[received_count-1].row);
			fclose(log_file);
#endif

			if(received_count >= k) {
				break;
			}
		}

		fec = fec->b_next;
	}

	if(received_count < k) {
		ortp_message("RSDecoder: decode failed, no enough packets, (%d, %d)", k, n);
#if defined(ANDROID) && defined(FEC_DEBUG)
		log_file = fopen("sdcard/test1.txt", "a+");
		fprintf(log_file, "RSDecoder: decode failed, no enough packets, (%d, %d)\n", k, n);
		fclose(log_file);
#endif
		for(decidx=0; decidx<received_source; decidx++) {
			free(block_info[decidx].data);
		}
		free(block_info);
		return FALSE;
	}
	
	ortp_message("RSDecoder: try decode block (%d~%d),k=%d,n=%d, size=%d", idx, idx+k-1, k, n, packet_size);
#if defined(ANDROID) && defined(FEC_DEBUG)
	log_file = fopen("sdcard/test1.txt", "a+");
	fprintf(log_file, "RSDecoder: try decode block (%d~%d),k=%d,n=%d, size=%d\n", idx, idx+k-1, k, n, packet_size);
	fclose(log_file);
#endif

	if (cauchy_256_decode(k, n-k, block_info, packet_size)) {
        // Decoding should never fail - indicates input is invalid
#if defined(ANDROID) && defined(FEC_DEBUG)
		log_file = fopen("sdcard/test1.txt", "a+");
		fprintf(log_file, "RSDecoder: decode failed, indicates input is invalid\n");
		fclose(log_file);
#endif
        return FALSE;
    }
	ortp_message("RSDecoder: decode succeed");

	for(decidx=received_source; decidx<received_count; decidx++) {
		int pkt_size = *((int*)block_info[decidx].data);
		unsigned char *pkt_data = block_info[decidx].data+sizeof(int);
		mblk_t *dec_rtp;
		rtp_header_t *rtp_header;

		//min_seq have been dequeued, packets earlier than is should be discarded
		ortp_message("RSDecoder: seq=%d, size=%d", ((rtp_header_t *)pkt_data)->seq_number, pkt_size);
		if(((rtp_header_t *)pkt_data)->seq_number <= min_seq){
			ortp_message("RSDecoder: overtime packet seq=%d", ((rtp_header_t *)pkt_data)->seq_number);
			continue;
		}
		dec_rtp = reconstruct_rtp_packet(pkt_data, pkt_size);
		rtp_header = (rtp_header_t *)dec_rtp->b_rptr;
		if(dec_rtp != NULL){
			rtp_session_rtp_parse(obj->parent.session,dec_rtp,user_ts,NULL,0);
			ortp_message("RSDecoder: recover and push rtp=%d", rtp_header->seq_number);
#if defined(ANDROID) && defined(FEC_DEBUG)
			log_file = fopen("sdcard/test1.txt", "a+");
			fprintf(log_file, "RSDecoder: recover and push rtp=%d\n", rtp_header->seq_number);
			fclose(log_file);
#endif
		}
	}

	//free memory: data of rtcp will be freed with the packet
	for(decidx=0; decidx<received_source; decidx++) {
		free(block_info[decidx].data);
	}
	free(block_info);

	return TRUE;
}

bool_t simple_fec_driver_incoming_rtp(MSFecDriver * baseobj, mblk_t * rtp, uint32_t user_ts){
	MSSimpleFecDriver *obj = (MSSimpleFecDriver *)baseobj;
	
	rtp_header_t *header = (rtp_header_t *)rtp->b_rptr;
	mblk_t *rtcp;

	rtcp = peekq(&obj->recv_fec);
#if defined(ANDROID) && defined(FEC_DEBUG)
	log_file = fopen("sdcard/test1.txt", "a+");
	fprintf(log_file, "fetching rtp, seq=%d\n", header->seq_number);
	fclose(log_file);
#endif

	if(rtcp == NULL){
		return FALSE;
	}
	
	//ortp_message("SimpleFecDriver: retrieved seq=%d, fec seq=%d", header->seq_number, rtcp_FEC_get_seq(rtcp));

	if(header->seq_number+2 >= rtcp_FEC_get_seq(rtcp)){
		uint16_t currseq = rtcp_FEC_get_seq(rtcp);
		simple_fec_driver_RS_decode((MSFecDriver *)obj, &obj->parent.session->rtp.rq, currseq, rtcp_FEC_get_source_num(rtcp), 
			rtcp_FEC_get_block_size(rtcp), user_ts, header->seq_number);

		while(rtcp != NULL && (rtcp_FEC_get_seq(rtcp) == currseq)) {
			ortp_message("SimpleFecDriver: deal and remove fec(%d,%d), left size=%d", rtcp_FEC_get_seq(rtcp), rtcp_FEC_get_index(rtcp), obj->recv_fec.q_mcount);
#if defined(ANDROID) && defined(FEC_DEBUG)
			log_file = fopen("sdcard/test1.txt", "a+");
			fprintf(log_file, "SimpleFecDriver: deal and remove fec(%d,%d), left size=%d\n", rtcp_FEC_get_seq(rtcp), rtcp_FEC_get_index(rtcp), obj->recv_fec.q_mcount);
			fclose(log_file);
#endif
			remq(&obj->recv_fec, rtcp);
			freemsg(rtcp);

			rtcp = peekq(&obj->recv_fec);
		}
	}
	
	return TRUE;
}

bool_t rtcp_fec_greater_than(uint16_t seq, uint16_t tmpseq, uint16_t idx, uint16_t tmpidx){
	if(seq > tmpseq || (seq == tmpseq && idx > tmpidx)) return TRUE;
	return FALSE;
}

//insert rtcp packet
static int simple_fec_driver_rtcp_putq_inc(queue_t *q, mblk_t *mp)
{
	mblk_t *tmp;
	uint16_t seq = rtcp_FEC_get_seq(mp);
	uint16_t index = rtcp_FEC_get_index(mp);
	/* insert message block by increasing time stamp order : the last (at the bottom)
		message of the queue is the newest*/
	//ortp_message("SimpleFecDriver:simple_fec_driver_rtcp_putq(): Enqueuing packet with seq=%i, index=%d",seq,index);

	if (qempty(q)) {
		putq(q,mp);
		return 0;
	}
	tmp=qbegin(q);
	/* we look at the queue from bottom to top, because enqueued packets have a better chance
	to be enqueued at the bottom, since there are surely newer */
	while (!qend(q,tmp))
	{
		uint16_t tmpseq = rtcp_FEC_get_seq(tmp);
		uint16_t tmpindex = rtcp_FEC_get_index(tmp);
		//ortp_message("SimpleFecDriver:simple_fec_driver_rtcp_putq(): Seeing packet with seq=%i, index=%d",tmpseq,tmpindex);

		if (seq == tmpseq && index == tmpindex)
		{
			/* this is a duplicated packet. Don't queue it */
			ortp_message("SimpleFecDriver:simple_fec_driver_rtcp_putq: duplicated message.");
			freemsg(mp);
			return -1;
		}else if (rtcp_fec_greater_than(seq, tmpseq, index, tmpindex)){
			tmp = tmp->b_next;
			continue;
		}
		else {
			insq(q, tmp, mp);
			return 0;
		}
	}
	/* this packet is the oldest, it has to be
	placed on top of the queue */
	putq(q, mp);
	return 0;
}

bool_t simple_fec_driver_process_rtcp(MSFecDriver * baseobj,mblk_t * rtcp){
	MSSimpleFecDriver *obj = (MSSimpleFecDriver *)baseobj;
	//ortp_message("SimpleFecDriver: process rtcp, driver[%p]", obj);

	mblk_t *duprtcp;
	unsigned char *s;
	int len;
	rtcp_FEC_get_data(rtcp,&s,&len);
	ortp_message("SimpleFecDriver: recv fec packet: (%d,%d),(%d,%d), data_len=%d\n", rtcp_FEC_get_seq(rtcp), rtcp_FEC_get_index(rtcp), rtcp_FEC_get_block_size(rtcp), 
		rtcp_FEC_get_source_num(rtcp), len);
#if defined(ANDROID) && defined(FEC_DEBUG)
	log_file = fopen("sdcard/test1.txt", "a+");
	fprintf(log_file, "SimpleFecDriver: recv fec packet: (%d-%d,%d),(%d,%d), data_len=%d\n", rtcp_FEC_get_seq(rtcp), rtcp_FEC_get_seq(rtcp)+rtcp_FEC_get_source_num(rtcp)-1, rtcp_FEC_get_index(rtcp), rtcp_FEC_get_block_size(rtcp), 
		rtcp_FEC_get_source_num(rtcp), len);
	fclose(log_file);
#endif

	//the original packet will be freed other place
	duprtcp = dupmsg(rtcp);
	simple_fec_driver_rtcp_putq_inc(&obj->recv_fec, duprtcp);
	
	return TRUE;
}

bool_t simple_fec_driver_flush(MSFecDriver * baseobj){
	MSSimpleFecDriver *obj = (MSSimpleFecDriver *)baseobj;
	//ortp_message("SimpleFecDriver: flush");
	return TRUE;
}

void simple_fec_driver_uinit(MSFecDriver * baseobj){
	MSSimpleFecDriver *obj = (MSSimpleFecDriver *)baseobj;
	//ortp_message("SimpleFecDriver: uinit");
#if defined(ANDROID) && defined(FEC_DEBUG)
	log_file = fopen("sdcard/test1.txt", "a+");
	fprintf(log_file, "simple fec driver destroyed. format=%d\n", obj->parent.format);
	fclose(log_file);
#endif
}


static MSFecDriverDesc simplefecdriverdesc={
	simple_fec_driver_outgoing_rtp,
	simple_fec_driver_incoming_rtp,
	simple_fec_driver_process_rtcp,
	simple_fec_driver_flush,
	simple_fec_driver_set_rate,
	simple_fec_driver_uinit
};

static MSFecDriverDesc mutefecdriverdesc={
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	simple_fec_driver_uinit
};

MSFecDriver * ms_simple_fec_driver_new(RtpSession *session, int format){
	MSSimpleFecDriver *obj = ortp_new0(MSSimpleFecDriver, 1);
	obj->parent.session = session;
	obj->parent.format = format;
	obj->parent.desc = format == 1 ? &simplefecdriverdesc : &mutefecdriverdesc;
	obj->source_packets = (unsigned char **)malloc(100 * sizeof(char*));
	obj->redundancy = NULL;
	obj->source_curr = 0;
	obj->last_ts = 0;
	obj->block_max = 0;
	qinit(&obj->recv_fec);
	
#if defined(ANDROID)
	log_file = fopen("sdcard/test1.txt", "a+");
	fprintf(log_file, "simple fec driver inited. format=%d\n", format);
	fclose(log_file);
#endif

	if (cauchy_256_init()) {
        // Wrong static library
        exit(1);
    }
	ortp_message("SimpleFecDriver: created driver [%p]", obj);
	
	return (MSFecDriver *)obj;
}

