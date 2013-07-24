#ifndef CHANNEL_H
#define CHANNEL_H

#include <openbsc/rtp_proxy.h>

void chan_do_dtmf(const char keypad, void *data);
void chan_do_write_frame(struct gsm_data_frame *dfr, void *data);
void chan_do_answer(struct rtp_socket *rtp_socket, uint32_t callref, void *data);
void *chan_do_outgoing_call(const char *dest, int callref);
void chan_do_hangup(uint32_t callref, void *data);

#endif
