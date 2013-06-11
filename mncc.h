
#ifndef MNCC_H
#define MNCC_H

int mncc_recv(struct gsm_network *net, struct msgb *msg);
int hack_call_phone(const char *dest);

#endif
