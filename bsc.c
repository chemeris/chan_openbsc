
#include <asterisk.h>
#include <asterisk/logger.h>

#include <osmocom/abis/e1_input.h>
#include <osmocom/abis/abis.h>
#include <osmocom/gsm/gsm0411_smc.h>
#include <osmocom/core/application.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <openbsc/bsc_api.h>
#include <openbsc/bss.h>
#include <openbsc/control_if.h>
#include <openbsc/debug.h>
#include <openbsc/db.h>
#include <openbsc/gsm_data.h>
#include <openbsc/handover_decision.h>
#include <openbsc/mncc.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/rrlp.h>
#include <openbsc/sms_queue.h>
#include <openbsc/token_auth.h>
#include <openbsc/vty.h>

#include <dbi/dbi.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "bsc.h"
#include "mncc.h"

void *tall_authciphop_ctx;
void *tall_bsc_ctx;
void *tall_call_ctx;
void *tall_ctr_ctx;
void *tall_fle_ctx;
void *tall_gsms_ctx;
void *tall_locop_ctx;
void *tall_map_ctx;
void *tall_msgb_ctx;
void *tall_paging_ctx;
void *tall_sigh_ctx;
void *tall_sub_req_ctx;
void *tall_subscr_ctx;
void *tall_tqe_ctx;
void *tall_trans_ctx;
void *tall_upq_ctx;

extern enum node_type bsc_vty_go_parent(struct vty *vty);

struct gsm_network *bsc_gsmnet = 0;
int ipacc_rtp_direct;

static struct vty_app_info vty_info = {
	.name		= "OpenBSC",
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

static int create_pcap_file(char *file)
{
        mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        int fd = open(file, O_WRONLY|O_TRUNC|O_CREAT, mode);

        if (fd < 0) {
                ast_log(LOG_ERROR, "Failed to open file for pcap\n");
                return -1;
        }

        e1_set_pcap_fd(fd);

        return 0;
}

void *openbsc_main(void *arg)
{
	ast_log(LOG_DEBUG, "openbsc main loop");
	while (1) {
		log_reset_context();
		osmo_select_main(0);
	}
}

static struct osmo_timer_list db_sync_timer;

/* timer to store statistics */
#define DB_SYNC_INTERVAL        60, 0
#define EXPIRE_INTERVAL         10, 0

static void subscr_expire_cb(void *data)
{
        subscr_expire(bsc_gsmnet);
        osmo_timer_schedule(&bsc_gsmnet->subscr_expire_timer, EXPIRE_INTERVAL);
}

/* timer handling */
static int _db_store_counter(struct osmo_counter *counter, void *data)
{
        return db_store_counter(counter);
}
static void db_sync_timer_cb(void *data)
{
        /* store counters to database and re-schedule */
        osmo_counters_for_each(_db_store_counter, NULL);
        osmo_timer_schedule(&db_sync_timer, DB_SYNC_INTERVAL);
}

int openbsc_init()
{
	int rc;

	create_pcap_file("/var/log/openbsc.log");

	srand(time(NULL));

	tall_bsc_ctx = talloc_named_const(NULL, 1, "openbsc");
	talloc_ctx_init();
	on_dso_load_token();
	on_dso_load_rrlp();
	on_dso_load_ho_dec();

	libosmo_abis_init(tall_bsc_ctx);
	osmo_init_logging(&log_info);
	bts_init();

	vty_init(&vty_info);
	bsc_vty_init(&log_info);

	log_parse_category_mask(osmo_stderr_target, "DMNCC:DRLL:DCC:DMM:DRR:DRSL:DNM");

	ipacc_rtp_direct = 0;

	rc = bsc_bootstrap_network(mncc_recv, /*mncc_recv_ast,*/ "/home/nib/coding/host-bsc/openbsc/openbsc/src/chan_openbsc/openbsc.cfg");
	if (rc < 0) {
		ast_log(LOG_ERROR, "Failed to bootstrap network\n");
		return -1;
	}

	bsc_api_init(bsc_gsmnet, msc_bsc_api());

	bsc_gsmnet->ctrl = controlif_setup(bsc_gsmnet, 4249);
	if (!bsc_gsmnet->ctrl) {
		ast_log(LOG_ERROR, "Failed to initialize control interface. Exiting.\n");
		return -1;
	}

	rc = db_init("/home/nib/coding/host-bsc/openbsc/openbsc/src/chan_openbsc/hlr.sqlite3");
	if (rc) {
		ast_log(LOG_ERROR, "DB: Failed to init database. Please check the option settings.\n");
		return -1;
	}

	ast_log(LOG_NOTICE, "DB: Database initialized.\n");

	rc = db_prepare();
	if (rc) {
		ast_log(LOG_ERROR, "DB: Failed to prepare database.\n");
		return -1;
	}

	ast_log(LOG_NOTICE, "DB: Database prepared.\n");


	db_sync_timer.cb = db_sync_timer_cb;
	db_sync_timer.data = NULL;
	osmo_timer_schedule(&db_sync_timer, DB_SYNC_INTERVAL);

        bsc_gsmnet->subscr_expire_timer.cb = subscr_expire_cb;
        bsc_gsmnet->subscr_expire_timer.data = NULL;
        osmo_timer_schedule(&bsc_gsmnet->subscr_expire_timer, EXPIRE_INTERVAL);

	osmo_init_ignore_signals();
	sms_queue_start(bsc_gsmnet, 20);

	ast_log(LOG_NOTICE, "Network bootstrapping done.\n");

	return 0;
}

