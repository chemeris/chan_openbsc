#ifndef CHANNEL_H
#define CHANNEL_H

#include <openbsc/rtp_proxy.h>
int do_write_frame(struct gsm_data_frame *dfr);
void do_answer(struct rtp_socket *rtp_socket);
void do_outgoing_call(const char *dest, int callref);

#endif
