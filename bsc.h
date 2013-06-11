
#ifndef BSC_H
#define BSC_H

extern struct gsm_network *bsc_gsmnet;
int openbsc_init();
void *openbsc_main(void *arg);

#endif
