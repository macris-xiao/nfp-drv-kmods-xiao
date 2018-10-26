// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2018 Netronome Systems, Inc. */

#include <linux/rtnetlink.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <net/red.h>

#include "../nfpcore/nfp_cpp.h"
#include "../nfp_app.h"
#include "../nfp_main.h"
#include "../nfp_net.h"
#include "../nfp_port.h"
#include "main.h"

static bool nfp_abm_qdisc_child_valid(struct nfp_qdisc *qdisc, unsigned int id)
{
	return qdisc->children[id] &&
	       qdisc->children[id] != NFP_QDISC_UNTRACKED;
}

static void *nfp_abm_qdisc_tree_deref_slot(void __rcu **slot)
{
	return rtnl_dereference(*slot);
}

static void
nfp_abm_qdisc_unlink_children(struct nfp_qdisc *qdisc,
			      unsigned int start, unsigned int end)
{
	unsigned int i;

	for (i = start; i < end; i++)
		if (nfp_abm_qdisc_child_valid(qdisc, i)) {
			qdisc->children[i]->use_cnt--;
			qdisc->children[i] = NULL;
		}
}

static void
nfp_abm_qdisc_clear_mq(struct net_device *netdev, struct nfp_abm_link *alink,
		       struct nfp_qdisc *qdisc)
{
	struct radix_tree_iter iter;
	unsigned int mq_refs = 0;
	void __rcu **slot;

	if (!qdisc->use_cnt)
		return;
	/* MQ doesn't notify well on destruction, we need special handling of
	 * MQ's children.
	 */
	if (qdisc->type == NFP_QDISC_MQ &&
	    qdisc == alink->root_qdisc &&
	    netdev->reg_state == NETREG_UNREGISTERING)
		return;

	/* Count refs held by MQ instances and clear pointers */
	radix_tree_for_each_slot(slot, &alink->qdiscs, &iter, 0) {
		struct nfp_qdisc *mq = nfp_abm_qdisc_tree_deref_slot(slot);
		unsigned int i;

		if (mq->type != NFP_QDISC_MQ || mq->netdev != netdev)
			continue;
		for (i = 0; i < mq->num_children; i++)
			if (mq->children[i] == qdisc) {
				mq->children[i] = NULL;
				mq_refs++;
			}
	}

	WARN(qdisc->use_cnt != mq_refs, "non-zero qdisc use count: %d (- %d)\n",
	     qdisc->use_cnt, mq_refs);
}

static void
nfp_abm_offload_compile_red(struct nfp_abm_link *alink,
			    struct nfp_red_qdisc *qdisc, unsigned int queue)
{
	if (!qdisc->handle)
		return;

	nfp_abm_ctrl_set_q_lvl(alink, queue, qdisc->threshold);
}

static void nfp_abm_offload_compile_one(struct nfp_abm_link *alink)
{
	unsigned int i;
	bool is_mq;

	is_mq = alink->num_qdiscs > 1;

	for (i = 0; i < alink->total_queues; i++) {
		struct nfp_red_qdisc *next;

		if (is_mq && !alink->red_qdiscs[i].handle)
			continue;

		next = is_mq ? &alink->red_qdiscs[i] : &alink->red_qdiscs[0];
		nfp_abm_offload_compile_red(alink, next, i);
	}
}

static void nfp_abm_offload_update(struct nfp_abm *abm)
{
	struct nfp_abm_link *alink = NULL;
	struct nfp_pf *pf = abm->app->pf;
	struct nfp_net *nn;
	size_t i;

	/* Mark all thresholds as unconfigured */
	__bitmap_set(abm->threshold_undef, 0, abm->num_thresholds);

	/* Configure all offloads */
	list_for_each_entry(nn, &pf->vnics, vnic_list) {
		alink = nn->app_priv;
		nfp_abm_offload_compile_one(alink);
	}

	/* Reset the unconfigured thresholds */
	for (i = 0; i < abm->num_thresholds; i++)
		if (test_bit(i, abm->threshold_undef))
			__nfp_abm_ctrl_set_q_lvl(abm, i, NFP_ABM_LVL_INFINITY);
}

static void
nfp_abm_qdisc_free(struct net_device *netdev, struct nfp_abm_link *alink,
		   struct nfp_qdisc *qdisc)
{
	struct nfp_port *port = nfp_port_from_netdev(netdev);

	if (!qdisc)
		return;
	nfp_abm_qdisc_clear_mq(netdev, alink, qdisc);
	WARN_ON(radix_tree_delete(&alink->qdiscs,
				  TC_H_MAJ(qdisc->handle)) != qdisc);

	kfree(qdisc->children);
	kfree(qdisc);

	port->tc_offload_cnt--;
}

static struct nfp_qdisc *
nfp_abm_qdisc_alloc(struct net_device *netdev, struct nfp_abm_link *alink,
		    enum nfp_qdisc_type type, u32 parent_handle, u32 handle,
		    unsigned int children)
{
	struct nfp_port *port = nfp_port_from_netdev(netdev);
	struct nfp_qdisc *qdisc;
	int err;

	qdisc = kzalloc(sizeof(*qdisc), GFP_KERNEL);
	if (!qdisc)
		return NULL;

	qdisc->children = kcalloc(children, sizeof(void *), GFP_KERNEL);
	if (!qdisc->children)
		goto err_free_qdisc;

	qdisc->netdev = netdev;
	qdisc->type = type;
	qdisc->parent_handle = parent_handle;
	qdisc->handle = handle;
	qdisc->num_children = children;

	err = radix_tree_insert(&alink->qdiscs, TC_H_MAJ(qdisc->handle), qdisc);
	if (err) {
		nfp_err(alink->abm->app->cpp,
			"Qdisc insertion into radix tree failed: %d\n", err);
		goto err_free_child_tbl;
	}

	port->tc_offload_cnt++;
	return qdisc;

err_free_child_tbl:
	kfree(qdisc->children);
err_free_qdisc:
	kfree(qdisc);
	return NULL;
}

static struct nfp_qdisc *
nfp_abm_qdisc_find(struct nfp_abm_link *alink, u32 handle)
{
	return radix_tree_lookup(&alink->qdiscs, TC_H_MAJ(handle));
}

static int
nfp_abm_qdisc_replace(struct net_device *netdev, struct nfp_abm_link *alink,
		      enum nfp_qdisc_type type, u32 parent_handle, u32 handle,
		      unsigned int children, struct nfp_qdisc **qdisc)
{
	*qdisc = nfp_abm_qdisc_find(alink, handle);
	if (*qdisc) {
		if (WARN_ON((*qdisc)->type != type))
			return -EINVAL;
		return 1;
	}

	*qdisc = nfp_abm_qdisc_alloc(netdev, alink, type, parent_handle, handle,
				     children);
	return *qdisc ? 0 : -ENOMEM;
}

static void
nfp_abm_qdisc_destroy(struct net_device *netdev, struct nfp_abm_link *alink,
		      u32 handle)
{
	struct nfp_qdisc *qdisc;

	qdisc = nfp_abm_qdisc_find(alink, handle);
	if (!qdisc)
		return;

	/* We don't get TC_SETUP_ROOT_QDISC w/ MQ when netdev is unregistered */
	if (alink->root_qdisc == qdisc)
		qdisc->use_cnt--;

	nfp_abm_qdisc_unlink_children(qdisc, 0, qdisc->num_children);
	nfp_abm_qdisc_free(netdev, alink, qdisc);

	if (alink->root_qdisc == qdisc)
		alink->root_qdisc = NULL;
}

static int
nfp_abm_qdisc_graft(struct nfp_abm_link *alink, u32 handle, u32 child_handle,
		    unsigned int id)
{
	struct nfp_qdisc *parent, *child;

	parent = nfp_abm_qdisc_find(alink, handle);
	if (!parent)
		return 0;

	if (WARN(id >= parent->num_children,
		 "graft child out of bound %d >= %d\n",
		 id, parent->num_children))
		return -EINVAL;

	nfp_abm_qdisc_unlink_children(parent, id, id + 1);

	child = nfp_abm_qdisc_find(alink, child_handle);
	if (child)
		child->use_cnt++;
	else
		child = NFP_QDISC_UNTRACKED;
	parent->children[id] = child;

	return 0;
}

static void
__nfp_abm_reset_root(struct net_device *netdev, struct nfp_abm_link *alink,
		     u32 handle, unsigned int qs, u32 init_val)
{
	memset(alink->red_qdiscs, 0,
	       sizeof(*alink->red_qdiscs) * alink->num_qdiscs);

	alink->parent = handle;
	alink->num_qdiscs = qs;
}

static void
nfp_abm_reset_root(struct net_device *netdev, struct nfp_abm_link *alink,
		   u32 handle, unsigned int qs)
{
	__nfp_abm_reset_root(netdev, alink, handle, qs, NFP_ABM_LVL_INFINITY);
}

static int
nfp_abm_red_find(struct nfp_abm_link *alink, struct tc_red_qopt_offload *opt)
{
	unsigned int i = TC_H_MIN(opt->parent) - 1;

	if (opt->parent == TC_H_ROOT)
		i = 0;
	else if (TC_H_MAJ(alink->parent) == TC_H_MAJ(opt->parent))
		i = TC_H_MIN(opt->parent) - 1;
	else
		return -EOPNOTSUPP;

	if (i >= alink->num_qdiscs ||
	    opt->handle != alink->red_qdiscs[i].handle)
		return -EOPNOTSUPP;

	return i;
}

static void
nfp_abm_red_destroy(struct net_device *netdev, struct nfp_abm_link *alink,
		    u32 handle)
{
	unsigned int i;

	nfp_abm_qdisc_destroy(netdev, alink, handle);

	for (i = 0; i < alink->num_qdiscs; i++)
		if (handle == alink->red_qdiscs[i].handle)
			break;
	if (i == alink->num_qdiscs)
		return;

	if (alink->parent == TC_H_ROOT)
		nfp_abm_reset_root(netdev, alink, TC_H_ROOT, 0);
	else
		memset(&alink->red_qdiscs[i], 0, sizeof(*alink->red_qdiscs));

	nfp_abm_offload_update(alink->abm);
}

static bool
nfp_abm_red_check_params(struct nfp_abm_link *alink,
			 struct tc_red_qopt_offload *opt)
{
	struct nfp_cpp *cpp = alink->abm->app->cpp;

	if (!opt->set.is_ecn) {
		nfp_warn(cpp, "RED offload failed - drop is not supported (ECN option required) (p:%08x h:%08x)\n",
			 opt->parent, opt->handle);
		return false;
	}
	if (opt->set.is_harddrop) {
		nfp_warn(cpp, "RED offload failed - harddrop is not supported (p:%08x h:%08x)\n",
			 opt->parent, opt->handle);
		return false;
	}
	if (opt->set.min != opt->set.max) {
		nfp_warn(cpp, "RED offload failed - unsupported min/max parameters (p:%08x h:%08x)\n",
			 opt->parent, opt->handle);
		return false;
	}
	if (opt->set.min > NFP_ABM_LVL_INFINITY) {
		nfp_warn(cpp, "RED offload failed - threshold too large %d > %d (p:%08x h:%08x)\n",
			 opt->set.min, NFP_ABM_LVL_INFINITY, opt->parent,
			 opt->handle);
		return false;
	}

	return true;
}

static int
nfp_abm_red_replace(struct net_device *netdev, struct nfp_abm_link *alink,
		    struct tc_red_qopt_offload *opt)
{
	struct nfp_qdisc *qdisc;
	bool existing;
	int i, err;
	int ret;

	ret = nfp_abm_qdisc_replace(netdev, alink, NFP_QDISC_RED, opt->parent,
				    opt->handle, 1, &qdisc);

	i = nfp_abm_red_find(alink, opt);
	existing = i >= 0;

	if (ret < 0) {
		err = ret;
		goto err_destroy;
	}

	/* If limit != 0 child gets reset */
	if (opt->set.limit) {
		if (nfp_abm_qdisc_child_valid(qdisc, 0))
			qdisc->children[0]->use_cnt--;
		qdisc->children[0] = NULL;
	} else {
		/* Qdisc was just allocated without a limit will use noop_qdisc,
		 * i.e. a block hole.
		 */
		if (!ret)
			qdisc->children[0] = NFP_QDISC_UNTRACKED;
	}

	if (!nfp_abm_red_check_params(alink, opt)) {
		err = -EINVAL;
		goto err_destroy;
	}

	if (existing) {
		nfp_abm_offload_update(alink->abm);
		return 0;
	}

	if (opt->parent == TC_H_ROOT) {
		i = 0;
		__nfp_abm_reset_root(netdev, alink, TC_H_ROOT, 1, opt->set.min);
	} else if (TC_H_MAJ(alink->parent) == TC_H_MAJ(opt->parent)) {
		i = TC_H_MIN(opt->parent) - 1;
	} else {
		return -EINVAL;
	}
	alink->red_qdiscs[i].handle = opt->handle;

	if (opt->parent == TC_H_ROOT)
		err = nfp_abm_ctrl_read_stats(alink,
					      &alink->red_qdiscs[i].stats);
	else
		err = nfp_abm_ctrl_read_q_stats(alink, i,
						&alink->red_qdiscs[i].stats);
	if (err)
		goto err_destroy;

	if (opt->parent == TC_H_ROOT)
		err = nfp_abm_ctrl_read_xstats(alink,
					       &alink->red_qdiscs[i].xstats);
	else
		err = nfp_abm_ctrl_read_q_xstats(alink, i,
						 &alink->red_qdiscs[i].xstats);
	if (err)
		goto err_destroy;

	alink->red_qdiscs[i].threshold = opt->set.min;
	alink->red_qdiscs[i].stats.backlog_pkts = 0;
	alink->red_qdiscs[i].stats.backlog_bytes = 0;

	nfp_abm_offload_update(alink->abm);

	return 0;
err_destroy:
	/* If the qdisc keeps on living, but we can't offload undo changes */
	if (existing) {
		opt->set.qstats->qlen -=
			alink->red_qdiscs[i].stats.backlog_pkts;
		opt->set.qstats->backlog -=
			alink->red_qdiscs[i].stats.backlog_bytes;
	}
	nfp_abm_red_destroy(netdev, alink, opt->handle);

	return err;
}

static void
nfp_abm_update_stats(struct nfp_alink_stats *new, struct nfp_alink_stats *old,
		     struct tc_qopt_offload_stats *stats)
{
	_bstats_update(stats->bstats, new->tx_bytes - old->tx_bytes,
		       new->tx_pkts - old->tx_pkts);
	stats->qstats->qlen += new->backlog_pkts - old->backlog_pkts;
	stats->qstats->backlog += new->backlog_bytes - old->backlog_bytes;
	stats->qstats->overlimits += new->overlimits - old->overlimits;
	stats->qstats->drops += new->drops - old->drops;
}

static int
nfp_abm_red_stats(struct nfp_abm_link *alink, struct tc_red_qopt_offload *opt)
{
	struct nfp_alink_stats *prev_stats;
	struct nfp_alink_stats stats;
	int i, err;

	i = nfp_abm_red_find(alink, opt);
	if (i < 0)
		return i;
	prev_stats = &alink->red_qdiscs[i].stats;

	if (alink->parent == TC_H_ROOT)
		err = nfp_abm_ctrl_read_stats(alink, &stats);
	else
		err = nfp_abm_ctrl_read_q_stats(alink, i, &stats);
	if (err)
		return err;

	nfp_abm_update_stats(&stats, prev_stats, &opt->stats);

	*prev_stats = stats;

	return 0;
}

static int
nfp_abm_red_xstats(struct nfp_abm_link *alink, struct tc_red_qopt_offload *opt)
{
	struct nfp_alink_xstats *prev_xstats;
	struct nfp_alink_xstats xstats;
	int i, err;

	i = nfp_abm_red_find(alink, opt);
	if (i < 0)
		return i;
	prev_xstats = &alink->red_qdiscs[i].xstats;

	if (alink->parent == TC_H_ROOT)
		err = nfp_abm_ctrl_read_xstats(alink, &xstats);
	else
		err = nfp_abm_ctrl_read_q_xstats(alink, i, &xstats);
	if (err)
		return err;

	opt->xstats->forced_mark += xstats.ecn_marked - prev_xstats->ecn_marked;
	opt->xstats->pdrop += xstats.pdrop - prev_xstats->pdrop;

	*prev_xstats = xstats;

	return 0;
}

int nfp_abm_setup_tc_red(struct net_device *netdev, struct nfp_abm_link *alink,
			 struct tc_red_qopt_offload *opt)
{
	switch (opt->command) {
	case TC_RED_REPLACE:
		return nfp_abm_red_replace(netdev, alink, opt);
	case TC_RED_DESTROY:
		nfp_abm_red_destroy(netdev, alink, opt->handle);
		return 0;
	case TC_RED_STATS:
		return nfp_abm_red_stats(alink, opt);
	case TC_RED_XSTATS:
		return nfp_abm_red_xstats(alink, opt);
	case TC_RED_GRAFT:
		return nfp_abm_qdisc_graft(alink, opt->handle,
					   opt->child_handle, 0);
	default:
		return -EOPNOTSUPP;
	}
}

static int
nfp_abm_mq_stats(struct nfp_abm_link *alink, struct tc_mq_qopt_offload *opt)
{
	struct nfp_alink_stats stats;
	unsigned int i;
	int err;

	for (i = 0; i < alink->num_qdiscs; i++) {
		if (alink->red_qdiscs[i].handle == TC_H_UNSPEC)
			continue;

		err = nfp_abm_ctrl_read_q_stats(alink, i, &stats);
		if (err)
			return err;

		nfp_abm_update_stats(&stats, &alink->red_qdiscs[i].stats,
				     &opt->stats);
	}

	return 0;
}

static int
nfp_abm_mq_create(struct net_device *netdev, struct nfp_abm_link *alink,
		  struct tc_mq_qopt_offload *opt)
{
	struct nfp_qdisc *qdisc;
	int ret;

	ret = nfp_abm_qdisc_replace(netdev, alink, NFP_QDISC_MQ,
				    TC_H_ROOT, opt->handle, alink->total_queues,
				    &qdisc);
	if (ret < 0)
		return ret;
	return 0;
}

int nfp_abm_setup_tc_mq(struct net_device *netdev, struct nfp_abm_link *alink,
			struct tc_mq_qopt_offload *opt)
{
	switch (opt->command) {
	case TC_MQ_CREATE:
		nfp_abm_reset_root(netdev, alink, opt->handle,
				   alink->total_queues);
		nfp_abm_offload_update(alink->abm);
		return nfp_abm_mq_create(netdev, alink, opt);
	case TC_MQ_DESTROY:
		nfp_abm_qdisc_destroy(netdev, alink, opt->handle);
		if (opt->handle == alink->parent) {
			nfp_abm_reset_root(netdev, alink, TC_H_ROOT, 0);
			nfp_abm_offload_update(alink->abm);
		}
		return 0;
	case TC_MQ_STATS:
		return nfp_abm_mq_stats(alink, opt);
	case TC_MQ_GRAFT:
		return nfp_abm_qdisc_graft(alink, opt->handle,
					   opt->graft_params.child_handle,
					   opt->graft_params.queue);
	default:
		return -EOPNOTSUPP;
	}
}

int nfp_abm_setup_root(struct net_device *netdev, struct nfp_abm_link *alink,
		       struct tc_root_qopt_offload *opt)
{
	if (opt->ingress)
		return -EOPNOTSUPP;
	if (alink->root_qdisc)
		alink->root_qdisc->use_cnt--;
	alink->root_qdisc = nfp_abm_qdisc_find(alink, opt->handle);
	if (alink->root_qdisc)
		alink->root_qdisc->use_cnt++;

	return 0;
}
