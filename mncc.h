
#ifndef MNCC_H
#define MNCC_H

int mncc_recv(struct gsm_network *net, struct msgb *msg);
int mncc_call_phone(const char *dest, void *data);
int mncc_connect_phone(uint32_t callref);
void mncc_hangup_phone(uint32_t callref);

#endif
