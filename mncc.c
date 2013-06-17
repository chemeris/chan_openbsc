/* mncc_builtin.c - default, minimal built-in MNCC Application for
 *		    standalone bsc_hack (netowrk-in-the-box mode) */

/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Andreas Eversberg <Andreas.Eversberg@versatel.de>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openbsc/gsm_04_08.h>
#include <openbsc/debug.h>
#include <openbsc/mncc.h>
#include <openbsc/mncc_int.h>
#include <osmocom/core/talloc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/transaction.h>
#include <openbsc/rtp_proxy.h>
#include <openbsc/gsm_subscriber.h>

#include "channel.h"
#include "bsc.h"
#include "mncc.h"

void *tall_call_ctx;

static LLIST_HEAD(call_list);

static uint32_t new_callref = 0x00000001;
struct gsm_trans *rem_trans;

static void free_call(struct gsm_call *call)
{
	llist_del(&call->entry);
	DEBUGP(DMNCC, "(call %x) Call removed.\n", call->callref);
	talloc_free(call);
}

static struct gsm_call *get_call_ref(uint32_t callref)
{
	struct gsm_call *callt;

	llist_for_each_entry(callt, &call_list, entry) {
		if (callt->callref == callref)
			return callt;
	}
	return NULL;
}

static uint8_t determine_lchan_mode(struct gsm_mncc *setup)
{
	/* FIXME: check codec capabilities of the phone */

	if (setup->lchan_type == GSM_LCHAN_TCH_F)
		return mncc_int.def_codec[0];
	else
		return mncc_int.def_codec[1];
}

/* on incoming call, look up database and send setup to remote subscr. */
static int mncc_setup_ind(struct gsm_call *call, int msg_type,
			  struct gsm_mncc *setup)
{
	struct gsm_mncc mncc;
	struct gsm_call *remote = NULL;
	struct gsm_subscriber *remote_subscr = NULL;

	memset(&mncc, 0, sizeof(struct gsm_mncc));
	mncc.callref = call->callref;

	/* already have remote call */
	if (call->remote_ref)
		return 0;

	/* transfer mode 1 would be packet mode, which was never specified */
	if (setup->bearer_cap.mode != 0) {
		LOGP(DMNCC, LOGL_NOTICE, "(call %x) We don't support "
			"packet mode\n", call->callref);
		mncc_set_cause(&mncc, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_BEARER_CA_UNAVAIL);
		goto out_reject;
	}

	/* we currently only do speech */
	if (setup->bearer_cap.transfer != GSM_MNCC_BCAP_SPEECH) {
		LOGP(DMNCC, LOGL_NOTICE, "(call %x) We only support "
			"voice calls\n", call->callref);
		mncc_set_cause(&mncc, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_BEARER_CA_UNAVAIL);
		goto out_reject;
	}

	remote_subscr = subscr_get_by_extension(bsc_gsmnet, setup->called.number);
	if (remote_subscr) {
		/* create remote call */
		if (!(remote = talloc_zero(tall_call_ctx, struct gsm_call))) {
			mncc_set_cause(&mncc, GSM48_CAUSE_LOC_PRN_S_LU,
					GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
			goto out_reject;
		}
		llist_add_tail(&remote->entry, &call_list);
		remote->net = call->net;
		remote->callref = new_callref++;
		DEBUGP(DMNCC, "(call %x) Creating new remote instance %x.\n",
			call->callref, remote->callref);

		/* link remote call */
		call->remote_ref = remote->callref;
		remote->remote_ref = call->callref;
	}

	/* send call proceeding */
	memset(&mncc, 0, sizeof(struct gsm_mncc));
	mncc.callref = call->callref;
	DEBUGP(DMNCC, "(call %x) Accepting call.\n", call->callref);
	mncc_tx_to_cc(call->net, MNCC_CALL_PROC_REQ, &mncc);

	/* modify mode */
	memset(&mncc, 0, sizeof(struct gsm_mncc));
	mncc.callref = call->callref;
	mncc.lchan_mode = determine_lchan_mode(setup);
	DEBUGP(DMNCC, "(call %x) Modify channel mode.\n", call->callref);
	mncc_tx_to_cc(call->net, MNCC_LCHAN_MODIFY, &mncc);

	if (remote_subscr) {
		/* send setup to remote */
		setup->callref = remote->callref;
		DEBUGP(DMNCC, "(call %x) Forwarding SETUP to remote.\n", call->callref);
		return mncc_tx_to_cc(remote->net, MNCC_SETUP_REQ, setup);
	} else {
		call->ext_ptr = do_outgoing_call(setup->called.number, call->callref);

		memset(&mncc, 0, sizeof(struct gsm_mncc));
		mncc.callref = call->callref;
		return mncc_tx_to_cc(call->net, MNCC_ALERT_REQ, &mncc);
	}

out_reject:
	mncc_tx_to_cc(call->net, MNCC_REJ_REQ, &mncc);
	free_call(call);
	return 0;
}

static int mncc_alert_ind(struct gsm_call *call, int msg_type,
			  struct gsm_mncc *alert)
{
	struct gsm_call *remote;

	/* send alerting to remote */
	if (!(remote = get_call_ref(call->remote_ref)))
		return 0;
	alert->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Forwarding ALERT to remote.\n", call->callref);
	return mncc_tx_to_cc(remote->net, MNCC_ALERT_REQ, alert);
}

static int mncc_notify_ind(struct gsm_call *call, int msg_type,
			   struct gsm_mncc *notify)
{
	struct gsm_call *remote;

	/* send notify to remote */
	if (!(remote = get_call_ref(call->remote_ref)))
		return 0;
	notify->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Forwarding NOTIF to remote.\n", call->callref);
	return mncc_tx_to_cc(remote->net, MNCC_NOTIFY_REQ, notify);
}

static int mncc_setup_cnf(struct gsm_call *call, int msg_type,
			  struct gsm_mncc *connect)
{
	struct gsm_mncc connect_ack, frame_recv;
	struct gsm_call *remote;
	uint32_t refs[2];

	/* acknowledge connect */
	memset(&connect_ack, 0, sizeof(struct gsm_mncc));
	connect_ack.callref = call->callref;
	DEBUGP(DMNCC, "(call %x) Acknowledge SETUP.\n", call->callref);
	mncc_tx_to_cc(call->net, MNCC_SETUP_COMPL_REQ, &connect_ack);

	/* send connect message to remote */
	if ((remote = get_call_ref(call->remote_ref))) {
		connect->callref = remote->callref;
		DEBUGP(DMNCC, "(call %x) Sending CONNECT to remote.\n", call->callref);
		mncc_tx_to_cc(remote->net, MNCC_SETUP_RSP, connect);
	}

	if (remote) {
		/* bridge tch */
		refs[0] = call->callref;
		refs[1] = call->remote_ref;
		DEBUGP(DMNCC, "(call %x) Bridging with remote.\n", call->callref);

		return mncc_tx_to_cc(call->net, MNCC_BRIDGE, refs);
	} else {
		memset(&frame_recv, 0, sizeof(struct gsm_mncc));
		frame_recv.callref = call->callref;
		return mncc_tx_to_cc(call->net, MNCC_FRAME_RECV, &frame_recv);
	}
}

static int mncc_disc_ind(struct gsm_call *call, int msg_type,
			 struct gsm_mncc *disc)
{
	struct gsm_call *remote;

	/* send release */
	DEBUGP(DMNCC, "(call %x) Releasing call with cause %d\n",
		call->callref, disc->cause.value);
	mncc_tx_to_cc(call->net, MNCC_REL_REQ, disc);

	/* send disc to remote */
	if (!(remote = get_call_ref(call->remote_ref))) {
		return 0;
	}
	disc->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Disconnecting remote with cause %d\n",
		remote->callref, disc->cause.value);
	return mncc_tx_to_cc(remote->net, MNCC_DISC_REQ, disc);
}

static int mncc_rel_ind(struct gsm_call *call, int msg_type, struct gsm_mncc *rel)
{
	struct gsm_call *remote;

	/* send release to remote */
	if (!(remote = get_call_ref(call->remote_ref))) {
		free_call(call);
		return 0;
	}

	rel->callref = remote->callref;
	DEBUGP(DMNCC, "(call %x) Releasing remote with cause %d\n",
		call->callref, rel->cause.value);

	/*
	 * Release this side of the call right now. Otherwise we end up
	 * in this method for the other call and will also try to release
	 * it and then we will end up with a double free and a crash
	 */
	free_call(call);
	mncc_tx_to_cc(remote->net, MNCC_REL_REQ, rel);

	return 0;
}

static int mncc_rel_cnf(struct gsm_call *call, int msg_type, struct gsm_mncc *rel)
{
	free_call(call);
	return 0;
}

/* receiving a TCH/F frame from the BSC code */
static int mncc_rcv_tchf(struct gsm_call *call, int msg_type,
			 struct gsm_data_frame *dfr)
{
	printf("mncc_recv_tchf\n");
	do_write_frame(dfr, call->ext_ptr);
	return 0;
}

int hack_connect_phone(uint32_t callref)
{
	DEBUGP(DMNCC, "hack_connect_phone: %d\n", callref);

	struct gsm_call *call = NULL, *callt;
	llist_for_each_entry(callt, &call_list, entry) {
		if (callt->callref == callref) {
			call = callt;
			break;
		}
	}

	struct gsm_trans *transmitter;
	struct gsm_mncc connect;

	memset(&connect, 0, sizeof(struct gsm_mncc));
	connect.callref = call->callref;
	DEBUGP(DMNCC, "(call %x) Sending CONNECT to remote.\n", call->callref);
	mncc_tx_to_cc(call->net, MNCC_SETUP_RSP, &connect);

	memset(&connect, 0, sizeof(struct gsm_mncc));
	connect.callref = call->callref;
	mncc_tx_to_cc(call->net, MNCC_FRAME_RECV, &connect);

	transmitter = trans_find_by_callref(call->net, call->callref);
	do_answer(transmitter->conn->lchan->abis_ip.rtp_socket, call->ext_ptr);

	return 0;
}

int hack_call_phone(const char *dest, void *data)
{
	struct gsm_subscriber *subscriber;
	subscriber = subscr_get_by_extension(bsc_gsmnet, dest);
	if (!subscriber)
		return -1;

	struct gsm_call *remote;
	/* create remote call */
	remote = talloc_zero(tall_call_ctx, struct gsm_call);
	if (remote == NULL) {
		return -1;
	}
	llist_add_tail(&remote->entry, &call_list);
	remote->net = bsc_gsmnet;
	remote->callref = new_callref++;
	remote->ext_ptr = data;
	DEBUGP(DMNCC, "Creating new remote instance %x.\n", remote->callref);

	struct gsm_mncc mncc;

	memset(&mncc, 0, sizeof(struct gsm_mncc));
	mncc.callref = remote->callref;
	mncc.fields |= MNCC_F_CALLING;
	strcpy(mncc.called.number, dest);
	mncc_tx_to_cc(bsc_gsmnet, MNCC_SETUP_REQ, &mncc);

	struct gsm_mncc frame_recv;

	memset(&frame_recv, 0, sizeof(struct gsm_mncc));
	frame_recv.callref = mncc.callref;
	mncc_tx_to_cc(bsc_gsmnet, MNCC_FRAME_RECV, &frame_recv);

	return 0;
}

/* Internal MNCC handler input function (from CC -> MNCC -> here) */
int mncc_recv(struct gsm_network *net, struct msgb *msg)
{
	void *arg = msgb_data(msg);
	struct gsm_mncc *data = arg;
	int msg_type = data->msg_type;
	int callref;
	struct gsm_call *call = NULL, *callt;
	struct gsm_trans *transmitter;
	int rc = 0;

	/* find callref */
	callref = data->callref;
	llist_for_each_entry(callt, &call_list, entry) {
		if (callt->callref == callref) {
			call = callt;
			break;
		}
	}

	/* create callref, if setup is received */
	if (!call) {
		if (!(call = talloc_zero(tall_call_ctx, struct gsm_call))) {
			struct gsm_mncc rel;

			memset(&rel, 0, sizeof(struct gsm_mncc));
			rel.callref = callref;
			mncc_set_cause(&rel, GSM48_CAUSE_LOC_PRN_S_LU,
				       GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
			mncc_tx_to_cc(net, MNCC_REL_REQ, &rel);
			goto out_free;
		}
		llist_add_tail(&call->entry, &call_list);
		call->net = net;
		call->callref = callref;
		DEBUGP(DMNCC, "(call %x) Call created.\n", call->callref);
	}

	switch (msg_type) {
	case GSM_TCHF_FRAME:
	case GSM_TCHF_FRAME_EFR:
		break;
	default:
		DEBUGP(DMNCC, "(call %x) Received message %s\n", call->callref,
			get_mncc_name(msg_type));
		break;
	}

	switch(msg_type) {
	case MNCC_SETUP_IND:
		rc = mncc_setup_ind(call, msg_type, arg);
		break;
	case MNCC_SETUP_CNF:
		rc = mncc_setup_cnf(call, msg_type, arg);
		if (!call->remote_ref) {
			transmitter = trans_find_by_callref(call->net, call->callref);
			do_answer(transmitter->conn->lchan->abis_ip.rtp_socket, call->ext_ptr);
		}
		break;
	case MNCC_SETUP_COMPL_IND:
		break;
	case MNCC_CALL_CONF_IND:
		/* we now need to MODIFY the channel */
		data->lchan_mode = determine_lchan_mode(data);
		mncc_tx_to_cc(call->net, MNCC_LCHAN_MODIFY, data);
		break;
	case MNCC_ALERT_IND:
		rc = mncc_alert_ind(call, msg_type, arg);
		break;
	case MNCC_NOTIFY_IND:
		rc = mncc_notify_ind(call, msg_type, arg);
		break;
	case MNCC_DISC_IND:
		rc = mncc_disc_ind(call, msg_type, arg);
		break;
	case MNCC_REL_IND:
	case MNCC_REJ_IND:
		rc = mncc_rel_ind(call, msg_type, arg);
		break;
	case MNCC_REL_CNF:
		rc = mncc_rel_cnf(call, msg_type, arg);
		break;
	case MNCC_FACILITY_IND:
		break;
	case MNCC_START_DTMF_IND:
		DEBUGP(DMNCC, "DTMF key: %c\n", data->keypad);
		do_dtmf(data->keypad, call->ext_ptr);
		rc = mncc_tx_to_cc(net, MNCC_START_DTMF_RSP, data);
		break;
	case MNCC_STOP_DTMF_IND:
		rc = mncc_tx_to_cc(net, MNCC_STOP_DTMF_RSP, data);
		break;
	case MNCC_MODIFY_IND:
		mncc_set_cause(data, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_SERV_OPT_UNIMPL);
		DEBUGP(DMNCC, "(call %x) Rejecting MODIFY with cause %d\n",
			call->callref, data->cause.value);
		rc = mncc_tx_to_cc(net, MNCC_MODIFY_REJ, data);
		break;
	case MNCC_MODIFY_CNF:
		break;
	case MNCC_HOLD_IND:
		mncc_set_cause(data, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_SERV_OPT_UNIMPL);
		DEBUGP(DMNCC, "(call %x) Rejecting HOLD with cause %d\n",
			call->callref, data->cause.value);
		rc = mncc_tx_to_cc(net, MNCC_HOLD_REJ, data);
		break;
	case MNCC_RETRIEVE_IND:
		mncc_set_cause(data, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_SERV_OPT_UNIMPL);
		DEBUGP(DMNCC, "(call %x) Rejecting RETRIEVE with cause %d\n",
			call->callref, data->cause.value);
		rc = mncc_tx_to_cc(net, MNCC_RETRIEVE_REJ, data);
		break;
	case GSM_TCHF_FRAME:
	case GSM_TCHF_FRAME_EFR:
		rc = mncc_rcv_tchf(call, msg_type, arg);
		break;
	default:
		LOGP(DMNCC, LOGL_NOTICE, "(call %x) Message unhandled\n", callref);
		break;
	}

out_free:
	msgb_free(msg);

	return rc;
}
