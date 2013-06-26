/*
 * OpenBSC Channel for Asterisk 11
 * <nicolas.bouliane@nutaq.com>
 */

#include <asterisk.h>

#include <asterisk/astdb.h>
#include <asterisk/causes.h>
#include <asterisk/channel.h>
#include <asterisk/channelstate.h>
#include <asterisk/cli.h>
#include <asterisk/io.h>
#include <asterisk/logger.h>
#include <asterisk/module.h>
#include <asterisk/netsock2.h>
#include <asterisk/pbx.h>
#include <asterisk/test.h>
#include <asterisk/rtp_engine.h>
#include <asterisk/sched.h>
#include <asterisk/utils.h>

#include <openbsc/rtp_proxy.h>

#include "bsc.h"
#include "config.h"
#include "mncc.h"

struct conf_infos *conf_info;
static struct ast_sched_context *sched = NULL;
static pthread_t g_main_tid;

static struct ast_format_cap *default_cap;
static struct ast_codec_pref default_prefs;

static struct ast_channel *cb_ast_request(const char *type,
						struct ast_format_cap *cap,
						const struct ast_channel *requestor,
						const char *destination,
						int *cause);
static int cb_ast_devicestate(const char *data);
static int cb_ast_call(struct ast_channel *channel, const char *dest, int timeout);
static int cb_ast_hangup(struct ast_channel *channel);
static int cb_ast_answer(struct ast_channel *channel);
static struct ast_frame *cb_ast_read(struct ast_channel *channel);
static int cb_ast_write(struct ast_channel *channel, struct ast_frame *frame);
static int cb_ast_indicate(struct ast_channel *channel, int ind, const void *data, size_t datalen);
static int cb_ast_fixup(struct ast_channel *oldchan, struct ast_channel *newchan);
static int cb_ast_senddigit_begin(struct ast_channel *channel, char digit);
static int cb_ast_senddigit_end(struct ast_channel *channel, char digit, unsigned int duration);

static enum ast_rtp_glue_result cb_ast_get_rtp_peer(struct ast_channel *channel, struct ast_rtp_instance **instance);
static int cb_ast_set_rtp_peer(struct ast_channel *channel,
					struct ast_rtp_instance *rtp,
					struct ast_rtp_instance *vrtp,
					struct ast_rtp_instance *trtp,
					const struct ast_format_cap *codecs,
					int nat_active);

static struct ast_channel_tech openbsc_tech = {
	.type			= "openbsc",
	.description		= "OpenBSC Asterisk Channel",
	.properties		= AST_CHAN_TP_WANTSJITTER | AST_CHAN_TP_CREATESJITTER,
	.requester		= cb_ast_request,
	.devicestate		= cb_ast_devicestate,
	.call			= cb_ast_call,
	.hangup			= cb_ast_hangup,
	.answer			= cb_ast_answer,
	.read			= cb_ast_read,
	.write			= cb_ast_write,
	.indicate		= cb_ast_indicate,
	.fixup			= cb_ast_fixup,
	.send_digit_begin	= cb_ast_senddigit_begin,
	.send_digit_end		= cb_ast_senddigit_end,
	.bridge			= ast_rtp_instance_bridge,
};

static struct ast_rtp_glue openbsc_rtp_glue = {
	.type			= "openbsc",
	.get_rtp_info		= cb_ast_get_rtp_peer,
	.update_peer		= cb_ast_set_rtp_peer,
};

struct subchannel {
	struct ast_rtp_instance *rtp;
	struct ast_channel *channel;
	struct addrinfo *res;
	struct rtp_socket *rs;
	uint32_t callref;
};

static int start_rtp(struct ast_channel *channel)
{
	ast_log(LOG_DEBUG, "start rtp\n");

	struct subchannel *subchan = NULL;
	struct ast_sockaddr bindaddr_tmp;

	if (channel == NULL) {
		ast_log(LOG_DEBUG, "channel is NULL\n");
		return -1;
	}

	subchan = ast_channel_tech_pvt(channel);
	if (subchan == NULL) {
		ast_log(LOG_DEBUG, "channel is NULL\n");
		return -1;
	}

	ast_parse_arg("0.0.0.0", PARSE_ADDR, &bindaddr_tmp);
	subchan->rtp = ast_rtp_instance_new("asterisk", sched, &bindaddr_tmp, NULL);

	if (subchan->rtp == NULL) {
		ast_log(LOG_DEBUG, "rtp is NULL\n");
		return -1;
	}

	ast_rtp_instance_set_prop(subchan->rtp, AST_RTP_PROPERTY_RTCP, 1);

	ast_channel_set_fd(channel, 0, ast_rtp_instance_fd(subchan->rtp, 0));
	ast_channel_set_fd(channel, 1, ast_rtp_instance_fd(subchan->rtp, 1));

	ast_rtp_instance_set_qos(subchan->rtp, 0, 0, "openbsc rtp");
	ast_rtp_instance_set_prop(subchan->rtp, AST_RTP_PROPERTY_NAT, 0);
	ast_rtp_codecs_packetization_set(ast_rtp_instance_get_codecs(subchan->rtp),
					subchan->rtp, &default_prefs);

	struct sockaddr_in local;
	struct ast_sockaddr local_tmp;

	ast_rtp_instance_get_local_address(subchan->rtp, &local_tmp);

	ast_sockaddr_to_sin(&local_tmp, &local);
	ast_log(LOG_DEBUG, "rtp local address: %s:%d\n", ast_inet_ntoa(local.sin_addr), ntohs(local.sin_port));

	subchan->rs = rtp_socket_create();
	rtp_socket_connect(subchan->rs, ntohl(local.sin_addr.s_addr), ntohs(local.sin_port));

	// set remote RTP

	struct sockaddr_in remote;
	struct ast_sockaddr remote_tmp;

	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = subchan->rs->rtp.sin_local.sin_addr.s_addr;
	remote.sin_port = subchan->rs->rtp.sin_local.sin_port;

	ast_sockaddr_from_sin(&remote_tmp, &remote);
	ast_rtp_instance_set_remote_address(subchan->rtp, &remote_tmp);

	return 0;
}

static struct ast_channel *openbsc_new_channel(const char *linkedid, const char *dest)
{
	struct ast_format tmpfmt;
	struct subchannel *subchan;
	struct ast_channel *channel;

	channel = ast_channel_alloc(	1,				/* needqueue */
					AST_STATE_DOWN,			/* state */
					"cid_num",			/* cid_num */
					"cid_name",			/* cid_name */
					"code",				/* code */
					dest,				/* extension */
					conf_info->context,		/* context */
					linkedid,			/* linked ID */
					0,				/* callnums */
					"openbsc/%s@%s-%d",
					"name",
					"dname",
					0);

	ast_format_cap_copy(ast_channel_nativeformats(channel), default_cap);
	ast_best_codec(ast_channel_nativeformats(channel), &tmpfmt);

	ast_format_copy(ast_channel_writeformat(channel), &tmpfmt);
	ast_format_copy(ast_channel_rawwriteformat(channel), &tmpfmt);
	ast_format_copy(ast_channel_readformat(channel), &tmpfmt);
	ast_format_copy(ast_channel_rawreadformat(channel), &tmpfmt);

	ast_channel_tech_set(channel, &openbsc_tech);

	subchan = calloc(1, sizeof(struct subchannel));
	ast_channel_tech_pvt_set(channel, subchan);

	subchan->channel = channel;

	return channel;
}

static struct ast_channel *cb_ast_request(const char *type,
						struct ast_format_cap *cap,
						const struct ast_channel *requestor,
						const char *destination,
						int *cause)
{
	struct ast_channel *channel;
	char buf[256];

	ast_log(LOG_DEBUG, "type: %s "
		"capability: %s "
		"destination: %s "
		"cause: %d\n",
		type, ast_getformatname_multiple(buf, sizeof(buf), cap),
		destination, *cause);

	channel = openbsc_new_channel(requestor ? ast_channel_linkedid(requestor) : NULL, "");
	return channel;
}

static int cb_ast_devicestate(const char *data)
{
	ast_log(LOG_NOTICE, "\n");
	return 0;
}

static int cb_ast_call(struct ast_channel *channel, const char *dest, int timeout)
{
	ast_log(LOG_NOTICE, "\n");

	struct subchannel *subchan;

	subchan = ast_channel_tech_pvt(channel);
	if (subchan == NULL) {
		ast_log(LOG_DEBUG, "subchan is NULL\n");
		return 0;
	}

        ast_setstate(channel, AST_STATE_RINGING);
        ast_queue_control(channel, AST_CONTROL_RINGING);

	ast_log(LOG_DEBUG, "Destination called: %s\n", dest);
	return hack_call_phone(dest, (void*)subchan);
}

static int cb_ast_hangup(struct ast_channel *channel)
{
	ast_log(LOG_NOTICE, "\n");

	struct subchannel *subchan = NULL;

	subchan = ast_channel_tech_pvt(channel);
	if (subchan == NULL) {
		ast_log(LOG_DEBUG, "subchan is NULL\n");
		return -1;
	}

	hack_hangup_phone(subchan->callref);

	if (subchan->rtp) {
		ast_rtp_instance_stop(subchan->rtp);
		ast_rtp_instance_destroy(subchan->rtp);
		subchan->rtp = NULL;
	}

	if (subchan->rs) {
		rtp_socket_free(subchan->rs);
		subchan->rs = NULL;
	}

	free(subchan);
	ast_channel_tech_pvt_set(channel, NULL);

	return 0;
}

static int cb_ast_answer(struct ast_channel *channel)
{
	ast_log(LOG_NOTICE, "\n");

	struct subchannel *subchan = NULL;

	subchan = ast_channel_tech_pvt(channel);
	if (subchan == NULL) {
		ast_log(LOG_DEBUG, "subchan is NULL\n");
		return -1;
	}

	hack_connect_phone(subchan->callref);
	return 0;
}

static struct ast_frame *cb_ast_read(struct ast_channel *channel)
{
	struct ast_frame *frame = NULL;
	struct subchannel *subchan = NULL;

	subchan = ast_channel_tech_pvt(channel);
	if (subchan == NULL) {
		ast_log(LOG_DEBUG, "subchan is NULL\n");
		return frame;
	}

	switch (ast_channel_fdno(channel)) {
	case 0:
		frame = ast_rtp_instance_read(subchan->rtp, 0);
		break;
	case 1:
		frame = ast_rtp_instance_read(subchan->rtp, 1);
		break;
	default:
		frame = &ast_null_frame;
	}

	if (frame && frame->frametype == AST_FRAME_VOICE) {
		if (!(ast_format_cap_iscompatible(ast_channel_nativeformats(channel), &frame->subclass.format))) {
			ast_format_cap_set(ast_channel_nativeformats(channel), &frame->subclass.format);
			ast_set_read_format(channel, ast_channel_readformat(channel));
			ast_set_write_format(channel, ast_channel_writeformat(channel));
		}
	}

	return frame;
}

static int cb_ast_write(struct ast_channel *channel, struct ast_frame *frame)
{
	struct subchannel *subchan = NULL;

	subchan = ast_channel_tech_pvt(channel);
	if (subchan == NULL) {
		ast_log(LOG_DEBUG, "subchan is NULL\n");
		return -1;
	}
	if (subchan->rtp)
		ast_rtp_instance_write(subchan->rtp, frame);
	return 0;
}

static int cb_ast_indicate(struct ast_channel *channel, int ind, const void *data, size_t datalen)
{
	ast_log(LOG_NOTICE, "\n");
	return 0;
}

static int cb_ast_fixup(struct ast_channel *oldchan, struct ast_channel *newchan)
{
	ast_log(LOG_NOTICE, "\n");
	return 0;
}

static int cb_ast_senddigit_begin(struct ast_channel *channel, char digit)
{
	ast_log(LOG_NOTICE, "\n");
	return 0;
}

static int cb_ast_senddigit_end(struct ast_channel *channel, char digit, unsigned int duration)
{
	ast_log(LOG_NOTICE, "\n");
	return 0;
}

static enum ast_rtp_glue_result cb_ast_get_rtp_peer(struct ast_channel *channel, struct ast_rtp_instance **instance)
{
	ast_log(LOG_NOTICE, "\n");

	struct subchannel *subchan;
	subchan = ast_channel_tech_pvt(channel);
	if (subchan == NULL) {
		ast_log(LOG_DEBUG, "subchan is NULL\n");
		return AST_RTP_GLUE_RESULT_FORBID;
	}

	if (subchan->rtp == NULL) {
		ast_log(LOG_DEBUG, "rtp is NULL\n");
		return AST_RTP_GLUE_RESULT_FORBID;
	}

	ao2_ref(subchan->rtp, +1);
	*instance = subchan->rtp;
	return AST_RTP_GLUE_RESULT_LOCAL;
}

static int cb_ast_set_rtp_peer(struct ast_channel *channel,
					struct ast_rtp_instance *rtp,
					struct ast_rtp_instance *vrtp,
					struct ast_rtp_instance *trtp,
					const struct ast_format_cap *codecs,
					int nat_active)
{

	ast_log(LOG_NOTICE, "\n");
	return -1;
}

void do_dtmf(const char keypad, void *data)
{
	struct subchannel *subchan;
	struct ast_frame frame = { AST_FRAME_DTMF, };

	subchan = data;
	if (subchan == NULL) {
		ast_log(LOG_DEBUG, "subchan is NULL\n");
		return;
	}

	if (subchan->channel == NULL) {
		ast_log(LOG_DEBUG, "channel is NULL\n");
		return;
	}

	frame.subclass.integer = keypad;
	frame.src = "openbsc";
	frame.len = 100;
	frame.offset = 0;
	frame.datalen = 0;

	ast_queue_frame(subchan->channel, &frame);
}

void *do_outgoing_call(const char *dest, uint32_t callref)
{
	ast_log(LOG_DEBUG, "outgoing call: %s::%u\n", dest, callref);

	struct subchannel *subchan;
	struct ast_channel *channel;

	channel = openbsc_new_channel(NULL, dest);
	if (channel == NULL) {
		ast_log(LOG_DEBUG, "channel is NULL\n");
		return NULL;
	}

	subchan = ast_channel_tech_pvt(channel);
	if (subchan == NULL) {
		ast_log(LOG_DEBUG, "subchan is NULL\n");
		return NULL;
	}

	subchan->callref = callref;

	ast_setstate(channel, AST_STATE_RING);
	ast_pbx_start(channel);

	return subchan;
}

void do_hangup(uint32_t callref, void *data)
{
	struct subchannel *subchan;
	struct ast_channel *channel;

	ast_log(LOG_NOTICE, "\n");

	subchan = data;
	if (subchan == NULL) {
		ast_log(LOG_DEBUG, "subchan is NULL\n");
		return;
	}

	channel = subchan->channel;
	if (channel == NULL) {
		ast_log(LOG_DEBUG, "channel is NULL\n");
		return;
	}

	ast_queue_hangup(channel);
}

void do_answer(struct rtp_socket *rtp_socket, uint32_t callref, void *data)
{
	struct subchannel *subchan;
	struct ast_channel *channel;

	subchan = data;
	if (subchan == NULL) {
		ast_log(LOG_DEBUG, "subchan is NULL\n");
		return;
	}

	channel = subchan->channel;
	if (channel == NULL) {
		ast_log(LOG_DEBUG, "channel is NULL\n");
		return;
	}

	subchan->callref = callref;
	ast_queue_control(channel, AST_CONTROL_ANSWER);
	start_rtp(channel);

	rtp_socket_proxy(subchan->rs, rtp_socket);
}

void do_write_frame(struct gsm_data_frame *dfr, void *data)
{
	struct subchannel *subchan;

	subchan = data;
	if (subchan == NULL) {
		ast_log(LOG_DEBUG, "subchan is NULL\n");
		return;
	}

	rtp_send_frame(subchan->rs, dfr);
}

static void rtp_init(void)
{
        ast_rtp_glue_register(&openbsc_rtp_glue);

        struct ast_format tmpfmt;
        default_cap = ast_format_cap_alloc();

        openbsc_tech.capabilities = ast_format_cap_alloc();

        ast_format_cap_add_all_by_type(openbsc_tech.capabilities, AST_FORMAT_TYPE_AUDIO);
        ast_format_cap_add(default_cap, ast_format_set(&tmpfmt, AST_FORMAT_GSM, 0));

        ast_parse_allow_disallow(&default_prefs, default_cap, "all", 1);
}

static int load_module(void)
{
	ast_log(LOG_NOTICE, "load OpenBSC module\n");

	config_init(&conf_info);

	ast_channel_register(&openbsc_tech);
	sched = ast_sched_context_create();
	rtp_init();

	if (openbsc_init(conf_info))
		return AST_MODULE_LOAD_DECLINE;

	pthread_create(&g_main_tid, NULL, openbsc_main, NULL);

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_log(LOG_NOTICE, "unload OpenBSC module\n");

	return 0;
}

static int reload_module(void)
{
	ast_log(LOG_NOTICE, "reload\n");
	return 0;
}

#define AST_MODULE "chan_openbsc"
AST_MODULE_INFO(

        ASTERISK_GPL_KEY,
        AST_MODFLAG_DEFAULT,
        "OpenBSC",
        .load = load_module,
        .reload = reload_module,
        .unload = unload_module,
        .load_pri = AST_MODPRI_CHANNEL_DRIVER,
);

