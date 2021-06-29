/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */
#ifndef __CN10K_TX_H__
#define __CN10K_TX_H__

#include <rte_vect.h>

#define NIX_TX_OFFLOAD_NONE	      (0)
#define NIX_TX_OFFLOAD_L3_L4_CSUM_F   BIT(0)
#define NIX_TX_OFFLOAD_OL3_OL4_CSUM_F BIT(1)
#define NIX_TX_OFFLOAD_VLAN_QINQ_F    BIT(2)
#define NIX_TX_OFFLOAD_MBUF_NOFF_F    BIT(3)
#define NIX_TX_OFFLOAD_TSO_F	      BIT(4)
#define NIX_TX_OFFLOAD_TSTAMP_F	      BIT(5)

/* Flags to control xmit_prepare function.
 * Defining it from backwards to denote its been
 * not used as offload flags to pick function
 */
#define NIX_TX_MULTI_SEG_F BIT(15)

#define NIX_TX_NEED_SEND_HDR_W1                                                \
	(NIX_TX_OFFLOAD_L3_L4_CSUM_F | NIX_TX_OFFLOAD_OL3_OL4_CSUM_F |         \
	 NIX_TX_OFFLOAD_VLAN_QINQ_F | NIX_TX_OFFLOAD_TSO_F)

#define NIX_TX_NEED_EXT_HDR                                                    \
	(NIX_TX_OFFLOAD_VLAN_QINQ_F | NIX_TX_OFFLOAD_TSTAMP_F |                \
	 NIX_TX_OFFLOAD_TSO_F)

#define NIX_XMIT_FC_OR_RETURN(txq, pkts)                                       \
	do {                                                                   \
		/* Cached value is low, Update the fc_cache_pkts */            \
		if (unlikely((txq)->fc_cache_pkts < (pkts))) {                 \
			/* Multiply with sqe_per_sqb to express in pkts */     \
			(txq)->fc_cache_pkts =                                 \
				((txq)->nb_sqb_bufs_adj - *(txq)->fc_mem)      \
				<< (txq)->sqes_per_sqb_log2;                   \
			/* Check it again for the room */                      \
			if (unlikely((txq)->fc_cache_pkts < (pkts)))           \
				return 0;                                      \
		}                                                              \
	} while (0)

#define LMT_OFF(lmt_addr, lmt_num, offset)                                     \
	(void *)((lmt_addr) + ((lmt_num) << ROC_LMT_LINE_SIZE_LOG2) + (offset))

/* Function to determine no of tx subdesc required in case ext
 * sub desc is enabled.
 */
static __rte_always_inline int
cn10k_nix_tx_ext_subs(const uint16_t flags)
{
	return (flags & NIX_TX_OFFLOAD_TSTAMP_F)
		       ? 2
		       : ((flags &
			   (NIX_TX_OFFLOAD_VLAN_QINQ_F | NIX_TX_OFFLOAD_TSO_F))
				  ? 1
				  : 0);
}

static __rte_always_inline uint8_t
cn10k_nix_pkts_per_vec_brst(const uint16_t flags)
{
	return ((flags & NIX_TX_NEED_EXT_HDR) ? 2 : 4)
	       << ROC_LMT_LINES_PER_CORE_LOG2;
}

static __rte_always_inline uint8_t
cn10k_nix_tx_dwords_per_line(const uint16_t flags)
{
	return (flags & NIX_TX_NEED_EXT_HDR) ?
			     ((flags & NIX_TX_OFFLOAD_TSTAMP_F) ? 8 : 6) :
			     8;
}

static __rte_always_inline uint64_t
cn10k_nix_tx_steor_data(const uint16_t flags)
{
	const uint64_t dw_m1 = cn10k_nix_tx_ext_subs(flags) + 1;
	uint64_t data;

	/* This will be moved to addr area */
	data = dw_m1;
	/* 15 vector sizes for single seg */
	data |= dw_m1 << 19;
	data |= dw_m1 << 22;
	data |= dw_m1 << 25;
	data |= dw_m1 << 28;
	data |= dw_m1 << 31;
	data |= dw_m1 << 34;
	data |= dw_m1 << 37;
	data |= dw_m1 << 40;
	data |= dw_m1 << 43;
	data |= dw_m1 << 46;
	data |= dw_m1 << 49;
	data |= dw_m1 << 52;
	data |= dw_m1 << 55;
	data |= dw_m1 << 58;
	data |= dw_m1 << 61;

	return data;
}

static __rte_always_inline uint64_t
cn10k_nix_tx_steor_vec_data(const uint16_t flags)
{
	const uint64_t dw_m1 = cn10k_nix_tx_dwords_per_line(flags) - 1;
	uint64_t data;

	/* This will be moved to addr area */
	data = dw_m1;
	/* 15 vector sizes for single seg */
	data |= dw_m1 << 19;
	data |= dw_m1 << 22;
	data |= dw_m1 << 25;
	data |= dw_m1 << 28;
	data |= dw_m1 << 31;
	data |= dw_m1 << 34;
	data |= dw_m1 << 37;
	data |= dw_m1 << 40;
	data |= dw_m1 << 43;
	data |= dw_m1 << 46;
	data |= dw_m1 << 49;
	data |= dw_m1 << 52;
	data |= dw_m1 << 55;
	data |= dw_m1 << 58;
	data |= dw_m1 << 61;

	return data;
}

static __rte_always_inline void
cn10k_nix_tx_skeleton(const struct cn10k_eth_txq *txq, uint64_t *cmd,
		      const uint16_t flags)
{
	/* Send hdr */
	cmd[0] = txq->send_hdr_w0;
	cmd[1] = 0;
	cmd += 2;

	/* Send ext if present */
	if (flags & NIX_TX_NEED_EXT_HDR) {
		*(__uint128_t *)cmd = *(const __uint128_t *)txq->cmd;
		cmd += 2;
	}

	/* Send sg */
	cmd[0] = txq->sg_w0;
	cmd[1] = 0;
}

static __rte_always_inline void
cn10k_nix_xmit_prepare_tso(struct rte_mbuf *m, const uint64_t flags)
{
	uint64_t mask, ol_flags = m->ol_flags;

	if (flags & NIX_TX_OFFLOAD_TSO_F && (ol_flags & PKT_TX_TCP_SEG)) {
		uintptr_t mdata = rte_pktmbuf_mtod(m, uintptr_t);
		uint16_t *iplen, *oiplen, *oudplen;
		uint16_t lso_sb, paylen;

		mask = -!!(ol_flags & (PKT_TX_OUTER_IPV4 | PKT_TX_OUTER_IPV6));
		lso_sb = (mask & (m->outer_l2_len + m->outer_l3_len)) +
			 m->l2_len + m->l3_len + m->l4_len;

		/* Reduce payload len from base headers */
		paylen = m->pkt_len - lso_sb;

		/* Get iplen position assuming no tunnel hdr */
		iplen = (uint16_t *)(mdata + m->l2_len +
				     (2 << !!(ol_flags & PKT_TX_IPV6)));
		/* Handle tunnel tso */
		if ((flags & NIX_TX_OFFLOAD_OL3_OL4_CSUM_F) &&
		    (ol_flags & PKT_TX_TUNNEL_MASK)) {
			const uint8_t is_udp_tun =
				(CNXK_NIX_UDP_TUN_BITMASK >>
				 ((ol_flags & PKT_TX_TUNNEL_MASK) >> 45)) &
				0x1;

			oiplen = (uint16_t *)(mdata + m->outer_l2_len +
					      (2 << !!(ol_flags &
						       PKT_TX_OUTER_IPV6)));
			*oiplen = rte_cpu_to_be_16(rte_be_to_cpu_16(*oiplen) -
						   paylen);

			/* Update format for UDP tunneled packet */
			if (is_udp_tun) {
				oudplen = (uint16_t *)(mdata + m->outer_l2_len +
						       m->outer_l3_len + 4);
				*oudplen = rte_cpu_to_be_16(
					rte_be_to_cpu_16(*oudplen) - paylen);
			}

			/* Update iplen position to inner ip hdr */
			iplen = (uint16_t *)(mdata + lso_sb - m->l3_len -
					     m->l4_len +
					     (2 << !!(ol_flags & PKT_TX_IPV6)));
		}

		*iplen = rte_cpu_to_be_16(rte_be_to_cpu_16(*iplen) - paylen);
	}
}

static __rte_always_inline void
cn10k_nix_xmit_prepare(struct rte_mbuf *m, uint64_t *cmd, uintptr_t lmt_addr,
		       const uint16_t flags, const uint64_t lso_tun_fmt)
{
	struct nix_send_ext_s *send_hdr_ext;
	struct nix_send_hdr_s *send_hdr;
	uint64_t ol_flags = 0, mask;
	union nix_send_hdr_w1_u w1;
	union nix_send_sg_s *sg;

	send_hdr = (struct nix_send_hdr_s *)cmd;
	if (flags & NIX_TX_NEED_EXT_HDR) {
		send_hdr_ext = (struct nix_send_ext_s *)(cmd + 2);
		sg = (union nix_send_sg_s *)(cmd + 4);
		/* Clear previous markings */
		send_hdr_ext->w0.lso = 0;
		send_hdr_ext->w1.u = 0;
	} else {
		sg = (union nix_send_sg_s *)(cmd + 2);
	}

	if (flags & NIX_TX_NEED_SEND_HDR_W1) {
		ol_flags = m->ol_flags;
		w1.u = 0;
	}

	if (!(flags & NIX_TX_MULTI_SEG_F)) {
		send_hdr->w0.total = m->data_len;
		send_hdr->w0.aura =
			roc_npa_aura_handle_to_aura(m->pool->pool_id);
	}

	/*
	 * L3type:  2 => IPV4
	 *          3 => IPV4 with csum
	 *          4 => IPV6
	 * L3type and L3ptr needs to be set for either
	 * L3 csum or L4 csum or LSO
	 *
	 */

	if ((flags & NIX_TX_OFFLOAD_OL3_OL4_CSUM_F) &&
	    (flags & NIX_TX_OFFLOAD_L3_L4_CSUM_F)) {
		const uint8_t csum = !!(ol_flags & PKT_TX_OUTER_UDP_CKSUM);
		const uint8_t ol3type =
			((!!(ol_flags & PKT_TX_OUTER_IPV4)) << 1) +
			((!!(ol_flags & PKT_TX_OUTER_IPV6)) << 2) +
			!!(ol_flags & PKT_TX_OUTER_IP_CKSUM);

		/* Outer L3 */
		w1.ol3type = ol3type;
		mask = 0xffffull << ((!!ol3type) << 4);
		w1.ol3ptr = ~mask & m->outer_l2_len;
		w1.ol4ptr = ~mask & (w1.ol3ptr + m->outer_l3_len);

		/* Outer L4 */
		w1.ol4type = csum + (csum << 1);

		/* Inner L3 */
		w1.il3type = ((!!(ol_flags & PKT_TX_IPV4)) << 1) +
			     ((!!(ol_flags & PKT_TX_IPV6)) << 2);
		w1.il3ptr = w1.ol4ptr + m->l2_len;
		w1.il4ptr = w1.il3ptr + m->l3_len;
		/* Increment it by 1 if it is IPV4 as 3 is with csum */
		w1.il3type = w1.il3type + !!(ol_flags & PKT_TX_IP_CKSUM);

		/* Inner L4 */
		w1.il4type = (ol_flags & PKT_TX_L4_MASK) >> 52;

		/* In case of no tunnel header use only
		 * shift IL3/IL4 fields a bit to use
		 * OL3/OL4 for header checksum
		 */
		mask = !ol3type;
		w1.u = ((w1.u & 0xFFFFFFFF00000000) >> (mask << 3)) |
		       ((w1.u & 0X00000000FFFFFFFF) >> (mask << 4));

	} else if (flags & NIX_TX_OFFLOAD_OL3_OL4_CSUM_F) {
		const uint8_t csum = !!(ol_flags & PKT_TX_OUTER_UDP_CKSUM);
		const uint8_t outer_l2_len = m->outer_l2_len;

		/* Outer L3 */
		w1.ol3ptr = outer_l2_len;
		w1.ol4ptr = outer_l2_len + m->outer_l3_len;
		/* Increment it by 1 if it is IPV4 as 3 is with csum */
		w1.ol3type = ((!!(ol_flags & PKT_TX_OUTER_IPV4)) << 1) +
			     ((!!(ol_flags & PKT_TX_OUTER_IPV6)) << 2) +
			     !!(ol_flags & PKT_TX_OUTER_IP_CKSUM);

		/* Outer L4 */
		w1.ol4type = csum + (csum << 1);

	} else if (flags & NIX_TX_OFFLOAD_L3_L4_CSUM_F) {
		const uint8_t l2_len = m->l2_len;

		/* Always use OLXPTR and OLXTYPE when only
		 * when one header is present
		 */

		/* Inner L3 */
		w1.ol3ptr = l2_len;
		w1.ol4ptr = l2_len + m->l3_len;
		/* Increment it by 1 if it is IPV4 as 3 is with csum */
		w1.ol3type = ((!!(ol_flags & PKT_TX_IPV4)) << 1) +
			     ((!!(ol_flags & PKT_TX_IPV6)) << 2) +
			     !!(ol_flags & PKT_TX_IP_CKSUM);

		/* Inner L4 */
		w1.ol4type = (ol_flags & PKT_TX_L4_MASK) >> 52;
	}

	if (flags & NIX_TX_NEED_EXT_HDR && flags & NIX_TX_OFFLOAD_VLAN_QINQ_F) {
		send_hdr_ext->w1.vlan1_ins_ena = !!(ol_flags & PKT_TX_VLAN);
		/* HW will update ptr after vlan0 update */
		send_hdr_ext->w1.vlan1_ins_ptr = 12;
		send_hdr_ext->w1.vlan1_ins_tci = m->vlan_tci;

		send_hdr_ext->w1.vlan0_ins_ena = !!(ol_flags & PKT_TX_QINQ);
		/* 2B before end of l2 header */
		send_hdr_ext->w1.vlan0_ins_ptr = 12;
		send_hdr_ext->w1.vlan0_ins_tci = m->vlan_tci_outer;
	}

	if (flags & NIX_TX_OFFLOAD_TSO_F && (ol_flags & PKT_TX_TCP_SEG)) {
		uint16_t lso_sb;
		uint64_t mask;

		mask = -(!w1.il3type);
		lso_sb = (mask & w1.ol4ptr) + (~mask & w1.il4ptr) + m->l4_len;

		send_hdr_ext->w0.lso_sb = lso_sb;
		send_hdr_ext->w0.lso = 1;
		send_hdr_ext->w0.lso_mps = m->tso_segsz;
		send_hdr_ext->w0.lso_format =
			NIX_LSO_FORMAT_IDX_TSOV4 + !!(ol_flags & PKT_TX_IPV6);
		w1.ol4type = NIX_SENDL4TYPE_TCP_CKSUM;

		/* Handle tunnel tso */
		if ((flags & NIX_TX_OFFLOAD_OL3_OL4_CSUM_F) &&
		    (ol_flags & PKT_TX_TUNNEL_MASK)) {
			const uint8_t is_udp_tun =
				(CNXK_NIX_UDP_TUN_BITMASK >>
				 ((ol_flags & PKT_TX_TUNNEL_MASK) >> 45)) &
				0x1;
			uint8_t shift = is_udp_tun ? 32 : 0;

			shift += (!!(ol_flags & PKT_TX_OUTER_IPV6) << 4);
			shift += (!!(ol_flags & PKT_TX_IPV6) << 3);

			w1.il4type = NIX_SENDL4TYPE_TCP_CKSUM;
			w1.ol4type = is_udp_tun ? NIX_SENDL4TYPE_UDP_CKSUM : 0;
			/* Update format for UDP tunneled packet */
			send_hdr_ext->w0.lso_format = (lso_tun_fmt >> shift);
		}
	}

	if (flags & NIX_TX_NEED_SEND_HDR_W1)
		send_hdr->w1.u = w1.u;

	if (!(flags & NIX_TX_MULTI_SEG_F)) {
		sg->seg1_size = m->data_len;
		*(rte_iova_t *)(sg + 1) = rte_mbuf_data_iova(m);

		if (flags & NIX_TX_OFFLOAD_MBUF_NOFF_F) {
			/* DF bit = 1 if refcount of current mbuf or parent mbuf
			 *		is greater than 1
			 * DF bit = 0 otherwise
			 */
			send_hdr->w0.df = cnxk_nix_prefree_seg(m);
		}
		/* Mark mempool object as "put" since it is freed by NIX */
		if (!send_hdr->w0.df)
			__mempool_check_cookies(m->pool, (void **)&m, 1, 0);
	}

	/* With minimal offloads, 'cmd' being local could be optimized out to
	 * registers. In other cases, 'cmd' will be in stack. Intent is
	 * 'cmd' stores content from txq->cmd which is copied only once.
	 */
	*((struct nix_send_hdr_s *)lmt_addr) = *send_hdr;
	lmt_addr += 16;
	if (flags & NIX_TX_NEED_EXT_HDR) {
		*((struct nix_send_ext_s *)lmt_addr) = *send_hdr_ext;
		lmt_addr += 16;
	}
	/* In case of multi-seg, sg template is stored here */
	*((union nix_send_sg_s *)lmt_addr) = *sg;
	*(rte_iova_t *)(lmt_addr + 8) = *(rte_iova_t *)(sg + 1);
}

static __rte_always_inline void
cn10k_nix_xmit_prepare_tstamp(uintptr_t lmt_addr, const uint64_t *cmd,
			      const uint64_t ol_flags, const uint16_t no_segdw,
			      const uint16_t flags)
{
	if (flags & NIX_TX_OFFLOAD_TSTAMP_F) {
		const uint8_t is_ol_tstamp = !(ol_flags & PKT_TX_IEEE1588_TMST);
		struct nix_send_ext_s *send_hdr_ext =
					(struct nix_send_ext_s *)lmt_addr + 16;
		uint64_t *lmt = (uint64_t *)lmt_addr;
		uint16_t off = (no_segdw - 1) << 1;
		struct nix_send_mem_s *send_mem;

		send_mem = (struct nix_send_mem_s *)(lmt + off);
		send_hdr_ext->w0.subdc = NIX_SUBDC_EXT;
		send_hdr_ext->w0.tstmp = 1;
		if (flags & NIX_TX_MULTI_SEG_F) {
			/* Retrieving the default desc values */
			lmt[off] = cmd[2];

			/* Using compiler barier to avoid voilation of C
			 * aliasing rules.
			 */
			rte_compiler_barrier();
		}

		/* Packets for which PKT_TX_IEEE1588_TMST is not set, tx tstamp
		 * should not be recorded, hence changing the alg type to
		 * NIX_SENDMEMALG_SET and also changing send mem addr field to
		 * next 8 bytes as it corrpt the actual tx tstamp registered
		 * address.
		 */
		send_mem->w0.subdc = NIX_SUBDC_MEM;
		send_mem->w0.alg = NIX_SENDMEMALG_SETTSTMP - (is_ol_tstamp);
		send_mem->addr =
			(rte_iova_t)(((uint64_t *)cmd[3]) + is_ol_tstamp);
	}
}

static __rte_always_inline uint16_t
cn10k_nix_prepare_mseg(struct rte_mbuf *m, uint64_t *cmd, const uint16_t flags)
{
	struct nix_send_hdr_s *send_hdr;
	union nix_send_sg_s *sg;
	struct rte_mbuf *m_next;
	uint64_t *slist, sg_u;
	uint64_t nb_segs;
	uint64_t segdw;
	uint8_t off, i;

	send_hdr = (struct nix_send_hdr_s *)cmd;
	send_hdr->w0.total = m->pkt_len;
	send_hdr->w0.aura = roc_npa_aura_handle_to_aura(m->pool->pool_id);

	if (flags & NIX_TX_NEED_EXT_HDR)
		off = 2;
	else
		off = 0;

	sg = (union nix_send_sg_s *)&cmd[2 + off];
	/* Clear sg->u header before use */
	sg->u &= 0xFC00000000000000;
	sg_u = sg->u;
	slist = &cmd[3 + off];

	i = 0;
	nb_segs = m->nb_segs;

	/* Fill mbuf segments */
	do {
		m_next = m->next;
		sg_u = sg_u | ((uint64_t)m->data_len << (i << 4));
		*slist = rte_mbuf_data_iova(m);
		/* Set invert df if buffer is not to be freed by H/W */
		if (flags & NIX_TX_OFFLOAD_MBUF_NOFF_F)
			sg_u |= (cnxk_nix_prefree_seg(m) << (i + 55));
			/* Mark mempool object as "put" since it is freed by NIX
			 */
#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
		if (!(sg_u & (1ULL << (i + 55))))
			__mempool_check_cookies(m->pool, (void **)&m, 1, 0);
#endif
		slist++;
		i++;
		nb_segs--;
		if (i > 2 && nb_segs) {
			i = 0;
			/* Next SG subdesc */
			*(uint64_t *)slist = sg_u & 0xFC00000000000000;
			sg->u = sg_u;
			sg->segs = 3;
			sg = (union nix_send_sg_s *)slist;
			sg_u = sg->u;
			slist++;
		}
		m = m_next;
	} while (nb_segs);

	sg->u = sg_u;
	sg->segs = i;
	segdw = (uint64_t *)slist - (uint64_t *)&cmd[2 + off];
	/* Roundup extra dwords to multiple of 2 */
	segdw = (segdw >> 1) + (segdw & 0x1);
	/* Default dwords */
	segdw += (off >> 1) + 1 + !!(flags & NIX_TX_OFFLOAD_TSTAMP_F);
	send_hdr->w0.sizem1 = segdw - 1;

	return segdw;
}

static __rte_always_inline uint16_t
cn10k_nix_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t pkts,
		    uint64_t *cmd, const uint16_t flags)
{
	struct cn10k_eth_txq *txq = tx_queue;
	const rte_iova_t io_addr = txq->io_addr;
	uintptr_t pa, lmt_addr = txq->lmt_base;
	uint16_t lmt_id, burst, left, i;
	uint64_t lso_tun_fmt;
	uint64_t data;

	NIX_XMIT_FC_OR_RETURN(txq, pkts);

	/* Get cmd skeleton */
	cn10k_nix_tx_skeleton(txq, cmd, flags);

	/* Reduce the cached count */
	txq->fc_cache_pkts -= pkts;

	if (flags & NIX_TX_OFFLOAD_TSO_F)
		lso_tun_fmt = txq->lso_tun_fmt;

	/* Get LMT base address and LMT ID as lcore id */
	ROC_LMT_BASE_ID_GET(lmt_addr, lmt_id);
	left = pkts;
again:
	burst = left > 32 ? 32 : left;
	for (i = 0; i < burst; i++) {
		/* Perform header writes for TSO, barrier at
		 * lmt steorl will suffice.
		 */
		if (flags & NIX_TX_OFFLOAD_TSO_F)
			cn10k_nix_xmit_prepare_tso(tx_pkts[i], flags);

		cn10k_nix_xmit_prepare(tx_pkts[i], cmd, lmt_addr, flags,
				       lso_tun_fmt);
		cn10k_nix_xmit_prepare_tstamp(lmt_addr, &txq->cmd[0],
					      tx_pkts[i]->ol_flags, 4, flags);
		lmt_addr += (1ULL << ROC_LMT_LINE_SIZE_LOG2);
	}

	/* Trigger LMTST */
	if (burst > 16) {
		data = cn10k_nix_tx_steor_data(flags);
		pa = io_addr | (data & 0x7) << 4;
		data &= ~0x7ULL;
		data |= (15ULL << 12);
		data |= (uint64_t)lmt_id;

		/* STEOR0 */
		roc_lmt_submit_steorl(data, pa);

		data = cn10k_nix_tx_steor_data(flags);
		pa = io_addr | (data & 0x7) << 4;
		data &= ~0x7ULL;
		data |= ((uint64_t)(burst - 17)) << 12;
		data |= (uint64_t)(lmt_id + 16);

		/* STEOR1 */
		roc_lmt_submit_steorl(data, pa);
	} else if (burst) {
		data = cn10k_nix_tx_steor_data(flags);
		pa = io_addr | (data & 0x7) << 4;
		data &= ~0x7ULL;
		data |= ((uint64_t)(burst - 1)) << 12;
		data |= lmt_id;

		/* STEOR0 */
		roc_lmt_submit_steorl(data, pa);
	}

	left -= burst;
	rte_io_wmb();
	if (left) {
		/* Start processing another burst */
		tx_pkts += burst;
		/* Reset lmt base addr */
		lmt_addr -= (1ULL << ROC_LMT_LINE_SIZE_LOG2);
		lmt_addr &= (~(BIT_ULL(ROC_LMT_BASE_PER_CORE_LOG2) - 1));
		goto again;
	}

	return pkts;
}

static __rte_always_inline uint16_t
cn10k_nix_xmit_pkts_mseg(void *tx_queue, struct rte_mbuf **tx_pkts,
			 uint16_t pkts, uint64_t *cmd, const uint16_t flags)
{
	struct cn10k_eth_txq *txq = tx_queue;
	uintptr_t pa0, pa1, lmt_addr = txq->lmt_base;
	const rte_iova_t io_addr = txq->io_addr;
	uint16_t segdw, lmt_id, burst, left, i;
	uint64_t data0, data1;
	uint64_t lso_tun_fmt;
	__uint128_t data128;
	uint16_t shft;

	NIX_XMIT_FC_OR_RETURN(txq, pkts);

	cn10k_nix_tx_skeleton(txq, cmd, flags);

	/* Reduce the cached count */
	txq->fc_cache_pkts -= pkts;

	if (flags & NIX_TX_OFFLOAD_TSO_F)
		lso_tun_fmt = txq->lso_tun_fmt;

	/* Get LMT base address and LMT ID as lcore id */
	ROC_LMT_BASE_ID_GET(lmt_addr, lmt_id);
	left = pkts;
again:
	burst = left > 32 ? 32 : left;
	shft = 16;
	data128 = 0;
	for (i = 0; i < burst; i++) {
		/* Perform header writes for TSO, barrier at
		 * lmt steorl will suffice.
		 */
		if (flags & NIX_TX_OFFLOAD_TSO_F)
			cn10k_nix_xmit_prepare_tso(tx_pkts[i], flags);

		cn10k_nix_xmit_prepare(tx_pkts[i], cmd, lmt_addr, flags,
				       lso_tun_fmt);
		/* Store sg list directly on lmt line */
		segdw = cn10k_nix_prepare_mseg(tx_pkts[i], (uint64_t *)lmt_addr,
					       flags);
		cn10k_nix_xmit_prepare_tstamp(lmt_addr, &txq->cmd[0],
					      tx_pkts[i]->ol_flags, segdw,
					      flags);
		lmt_addr += (1ULL << ROC_LMT_LINE_SIZE_LOG2);
		data128 |= (((__uint128_t)(segdw - 1)) << shft);
		shft += 3;
	}

	data0 = (uint64_t)data128;
	data1 = (uint64_t)(data128 >> 64);
	/* Make data0 similar to data1 */
	data0 >>= 16;
	/* Trigger LMTST */
	if (burst > 16) {
		pa0 = io_addr | (data0 & 0x7) << 4;
		data0 &= ~0x7ULL;
		/* Move lmtst1..15 sz to bits 63:19 */
		data0 <<= 16;
		data0 |= (15ULL << 12);
		data0 |= (uint64_t)lmt_id;

		/* STEOR0 */
		roc_lmt_submit_steorl(data0, pa0);

		pa1 = io_addr | (data1 & 0x7) << 4;
		data1 &= ~0x7ULL;
		data1 <<= 16;
		data1 |= ((uint64_t)(burst - 17)) << 12;
		data1 |= (uint64_t)(lmt_id + 16);

		/* STEOR1 */
		roc_lmt_submit_steorl(data1, pa1);
	} else if (burst) {
		pa0 = io_addr | (data0 & 0x7) << 4;
		data0 &= ~0x7ULL;
		/* Move lmtst1..15 sz to bits 63:19 */
		data0 <<= 16;
		data0 |= ((burst - 1) << 12);
		data0 |= (uint64_t)lmt_id;

		/* STEOR0 */
		roc_lmt_submit_steorl(data0, pa0);
	}

	left -= burst;
	rte_io_wmb();
	if (left) {
		/* Start processing another burst */
		tx_pkts += burst;
		/* Reset lmt base addr */
		lmt_addr -= (1ULL << ROC_LMT_LINE_SIZE_LOG2);
		lmt_addr &= (~(BIT_ULL(ROC_LMT_BASE_PER_CORE_LOG2) - 1));
		goto again;
	}

	return pkts;
}

#if defined(RTE_ARCH_ARM64)

static __rte_always_inline void
cn10k_nix_prepare_tso(struct rte_mbuf *m, union nix_send_hdr_w1_u *w1,
		      union nix_send_ext_w0_u *w0, uint64_t ol_flags,
		      const uint64_t flags, const uint64_t lso_tun_fmt)
{
	uint16_t lso_sb;
	uint64_t mask;

	if (!(ol_flags & PKT_TX_TCP_SEG))
		return;

	mask = -(!w1->il3type);
	lso_sb = (mask & w1->ol4ptr) + (~mask & w1->il4ptr) + m->l4_len;

	w0->u |= BIT(14);
	w0->lso_sb = lso_sb;
	w0->lso_mps = m->tso_segsz;
	w0->lso_format = NIX_LSO_FORMAT_IDX_TSOV4 + !!(ol_flags & PKT_TX_IPV6);
	w1->ol4type = NIX_SENDL4TYPE_TCP_CKSUM;

	/* Handle tunnel tso */
	if ((flags & NIX_TX_OFFLOAD_OL3_OL4_CSUM_F) &&
	    (ol_flags & PKT_TX_TUNNEL_MASK)) {
		const uint8_t is_udp_tun =
			(CNXK_NIX_UDP_TUN_BITMASK >>
			 ((ol_flags & PKT_TX_TUNNEL_MASK) >> 45)) &
			0x1;
		uint8_t shift = is_udp_tun ? 32 : 0;

		shift += (!!(ol_flags & PKT_TX_OUTER_IPV6) << 4);
		shift += (!!(ol_flags & PKT_TX_IPV6) << 3);

		w1->il4type = NIX_SENDL4TYPE_TCP_CKSUM;
		w1->ol4type = is_udp_tun ? NIX_SENDL4TYPE_UDP_CKSUM : 0;
		/* Update format for UDP tunneled packet */

		w0->lso_format = (lso_tun_fmt >> shift);
	}
}

#define NIX_DESCS_PER_LOOP 4
static __rte_always_inline uint16_t
cn10k_nix_xmit_pkts_vector(void *tx_queue, struct rte_mbuf **tx_pkts,
			   uint16_t pkts, uint64_t *cmd, const uint16_t flags)
{
	uint64x2_t dataoff_iova0, dataoff_iova1, dataoff_iova2, dataoff_iova3;
	uint64x2_t len_olflags0, len_olflags1, len_olflags2, len_olflags3;
	uint64x2_t cmd0[NIX_DESCS_PER_LOOP], cmd1[NIX_DESCS_PER_LOOP],
		cmd2[NIX_DESCS_PER_LOOP], cmd3[NIX_DESCS_PER_LOOP];
	uint64_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, data, pa;
	uint64x2_t senddesc01_w0, senddesc23_w0;
	uint64x2_t senddesc01_w1, senddesc23_w1;
	uint16_t left, scalar, burst, i, lmt_id;
	uint64x2_t sendext01_w0, sendext23_w0;
	uint64x2_t sendext01_w1, sendext23_w1;
	uint64x2_t sendmem01_w0, sendmem23_w0;
	uint64x2_t sendmem01_w1, sendmem23_w1;
	uint64x2_t sgdesc01_w0, sgdesc23_w0;
	uint64x2_t sgdesc01_w1, sgdesc23_w1;
	struct cn10k_eth_txq *txq = tx_queue;
	uintptr_t laddr = txq->lmt_base;
	rte_iova_t io_addr = txq->io_addr;
	uint64x2_t ltypes01, ltypes23;
	uint64x2_t xtmp128, ytmp128;
	uint64x2_t xmask01, xmask23;
	uint8_t lnum;

	NIX_XMIT_FC_OR_RETURN(txq, pkts);

	scalar = pkts & (NIX_DESCS_PER_LOOP - 1);
	pkts = RTE_ALIGN_FLOOR(pkts, NIX_DESCS_PER_LOOP);

	/* Reduce the cached count */
	txq->fc_cache_pkts -= pkts;
	/* Perform header writes before barrier for TSO */
	if (flags & NIX_TX_OFFLOAD_TSO_F) {
		for (i = 0; i < pkts; i++)
			cn10k_nix_xmit_prepare_tso(tx_pkts[i], flags);
	}

	senddesc01_w0 = vld1q_dup_u64(&txq->send_hdr_w0);
	senddesc23_w0 = senddesc01_w0;
	senddesc01_w1 = vdupq_n_u64(0);
	senddesc23_w1 = senddesc01_w1;
	sgdesc01_w0 = vld1q_dup_u64(&txq->sg_w0);
	sgdesc23_w0 = sgdesc01_w0;

	/* Load command defaults into vector variables. */
	if (flags & NIX_TX_NEED_EXT_HDR) {
		sendext01_w0 = vld1q_dup_u64(&txq->cmd[0]);
		sendext23_w0 = sendext01_w0;
		sendext01_w1 = vdupq_n_u64(12 | 12U << 24);
		sendext23_w1 = sendext01_w1;
		if (flags & NIX_TX_OFFLOAD_TSTAMP_F) {
			sendmem01_w0 = vld1q_dup_u64(&txq->cmd[2]);
			sendmem23_w0 = sendmem01_w0;
			sendmem01_w1 = vld1q_dup_u64(&txq->cmd[3]);
			sendmem23_w1 = sendmem01_w1;
		}
	}

	/* Get LMT base address and LMT ID as lcore id */
	ROC_LMT_BASE_ID_GET(laddr, lmt_id);
	left = pkts;
again:
	/* Number of packets to prepare depends on offloads enabled. */
	burst = left > cn10k_nix_pkts_per_vec_brst(flags) ?
			      cn10k_nix_pkts_per_vec_brst(flags) :
			      left;
	lnum = 0;
	for (i = 0; i < burst; i += NIX_DESCS_PER_LOOP) {
		/* Clear lower 32bit of SEND_HDR_W0 and SEND_SG_W0 */
		senddesc01_w0 =
			vbicq_u64(senddesc01_w0, vdupq_n_u64(0xFFFFFFFF));
		sgdesc01_w0 = vbicq_u64(sgdesc01_w0, vdupq_n_u64(0xFFFFFFFF));

		senddesc23_w0 = senddesc01_w0;
		sgdesc23_w0 = sgdesc01_w0;

		/* Clear vlan enables. */
		if (flags & NIX_TX_NEED_EXT_HDR) {
			sendext01_w1 = vbicq_u64(sendext01_w1,
						 vdupq_n_u64(0x3FFFF00FFFF00));
			sendext23_w1 = sendext01_w1;
		}

		if (flags & NIX_TX_OFFLOAD_TSTAMP_F) {
			/* Reset send mem alg to SETTSTMP from SUB*/
			sendmem01_w0 = vbicq_u64(sendmem01_w0,
						 vdupq_n_u64(BIT_ULL(59)));
			/* Reset send mem address to default. */
			sendmem01_w1 =
				vbicq_u64(sendmem01_w1, vdupq_n_u64(0xF));
			sendmem23_w0 = sendmem01_w0;
			sendmem23_w1 = sendmem01_w1;
		}

		if (flags & NIX_TX_OFFLOAD_TSO_F) {
			/* Clear the LSO enable bit. */
			sendext01_w0 = vbicq_u64(sendext01_w0,
						 vdupq_n_u64(BIT_ULL(14)));
			sendext23_w0 = sendext01_w0;
		}

		/* Move mbufs to iova */
		mbuf0 = (uint64_t *)tx_pkts[0];
		mbuf1 = (uint64_t *)tx_pkts[1];
		mbuf2 = (uint64_t *)tx_pkts[2];
		mbuf3 = (uint64_t *)tx_pkts[3];

		mbuf0 = (uint64_t *)((uintptr_t)mbuf0 +
				     offsetof(struct rte_mbuf, buf_iova));
		mbuf1 = (uint64_t *)((uintptr_t)mbuf1 +
				     offsetof(struct rte_mbuf, buf_iova));
		mbuf2 = (uint64_t *)((uintptr_t)mbuf2 +
				     offsetof(struct rte_mbuf, buf_iova));
		mbuf3 = (uint64_t *)((uintptr_t)mbuf3 +
				     offsetof(struct rte_mbuf, buf_iova));
		/*
		 * Get mbuf's, olflags, iova, pktlen, dataoff
		 * dataoff_iovaX.D[0] = iova,
		 * dataoff_iovaX.D[1](15:0) = mbuf->dataoff
		 * len_olflagsX.D[0] = ol_flags,
		 * len_olflagsX.D[1](63:32) = mbuf->pkt_len
		 */
		dataoff_iova0 = vld1q_u64(mbuf0);
		len_olflags0 = vld1q_u64(mbuf0 + 2);
		dataoff_iova1 = vld1q_u64(mbuf1);
		len_olflags1 = vld1q_u64(mbuf1 + 2);
		dataoff_iova2 = vld1q_u64(mbuf2);
		len_olflags2 = vld1q_u64(mbuf2 + 2);
		dataoff_iova3 = vld1q_u64(mbuf3);
		len_olflags3 = vld1q_u64(mbuf3 + 2);

		/* Move mbufs to point pool */
		mbuf0 = (uint64_t *)((uintptr_t)mbuf0 +
				     offsetof(struct rte_mbuf, pool) -
				     offsetof(struct rte_mbuf, buf_iova));
		mbuf1 = (uint64_t *)((uintptr_t)mbuf1 +
				     offsetof(struct rte_mbuf, pool) -
				     offsetof(struct rte_mbuf, buf_iova));
		mbuf2 = (uint64_t *)((uintptr_t)mbuf2 +
				     offsetof(struct rte_mbuf, pool) -
				     offsetof(struct rte_mbuf, buf_iova));
		mbuf3 = (uint64_t *)((uintptr_t)mbuf3 +
				     offsetof(struct rte_mbuf, pool) -
				     offsetof(struct rte_mbuf, buf_iova));

		if (flags & (NIX_TX_OFFLOAD_OL3_OL4_CSUM_F |
			     NIX_TX_OFFLOAD_L3_L4_CSUM_F)) {
			/* Get tx_offload for ol2, ol3, l2, l3 lengths */
			/*
			 * E(8):OL2_LEN(7):OL3_LEN(9):E(24):L3_LEN(9):L2_LEN(7)
			 * E(8):OL2_LEN(7):OL3_LEN(9):E(24):L3_LEN(9):L2_LEN(7)
			 */

			asm volatile("LD1 {%[a].D}[0],[%[in]]\n\t"
				     : [a] "+w"(senddesc01_w1)
				     : [in] "r"(mbuf0 + 2)
				     : "memory");

			asm volatile("LD1 {%[a].D}[1],[%[in]]\n\t"
				     : [a] "+w"(senddesc01_w1)
				     : [in] "r"(mbuf1 + 2)
				     : "memory");

			asm volatile("LD1 {%[b].D}[0],[%[in]]\n\t"
				     : [b] "+w"(senddesc23_w1)
				     : [in] "r"(mbuf2 + 2)
				     : "memory");

			asm volatile("LD1 {%[b].D}[1],[%[in]]\n\t"
				     : [b] "+w"(senddesc23_w1)
				     : [in] "r"(mbuf3 + 2)
				     : "memory");

			/* Get pool pointer alone */
			mbuf0 = (uint64_t *)*mbuf0;
			mbuf1 = (uint64_t *)*mbuf1;
			mbuf2 = (uint64_t *)*mbuf2;
			mbuf3 = (uint64_t *)*mbuf3;
		} else {
			/* Get pool pointer alone */
			mbuf0 = (uint64_t *)*mbuf0;
			mbuf1 = (uint64_t *)*mbuf1;
			mbuf2 = (uint64_t *)*mbuf2;
			mbuf3 = (uint64_t *)*mbuf3;
		}

		const uint8x16_t shuf_mask2 = {
			0x4, 0x5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xc, 0xd, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		};
		xtmp128 = vzip2q_u64(len_olflags0, len_olflags1);
		ytmp128 = vzip2q_u64(len_olflags2, len_olflags3);

		/* Clear dataoff_iovaX.D[1] bits other than dataoff(15:0) */
		const uint64x2_t and_mask0 = {
			0xFFFFFFFFFFFFFFFF,
			0x000000000000FFFF,
		};

		dataoff_iova0 = vandq_u64(dataoff_iova0, and_mask0);
		dataoff_iova1 = vandq_u64(dataoff_iova1, and_mask0);
		dataoff_iova2 = vandq_u64(dataoff_iova2, and_mask0);
		dataoff_iova3 = vandq_u64(dataoff_iova3, and_mask0);

		/*
		 * Pick only 16 bits of pktlen preset at bits 63:32
		 * and place them at bits 15:0.
		 */
		xtmp128 = vqtbl1q_u8(xtmp128, shuf_mask2);
		ytmp128 = vqtbl1q_u8(ytmp128, shuf_mask2);

		/* Add pairwise to get dataoff + iova in sgdesc_w1 */
		sgdesc01_w1 = vpaddq_u64(dataoff_iova0, dataoff_iova1);
		sgdesc23_w1 = vpaddq_u64(dataoff_iova2, dataoff_iova3);

		/* Orr both sgdesc_w0 and senddesc_w0 with 16 bits of
		 * pktlen at 15:0 position.
		 */
		sgdesc01_w0 = vorrq_u64(sgdesc01_w0, xtmp128);
		sgdesc23_w0 = vorrq_u64(sgdesc23_w0, ytmp128);
		senddesc01_w0 = vorrq_u64(senddesc01_w0, xtmp128);
		senddesc23_w0 = vorrq_u64(senddesc23_w0, ytmp128);

		/* Move mbuf to point to pool_id. */
		mbuf0 = (uint64_t *)((uintptr_t)mbuf0 +
				     offsetof(struct rte_mempool, pool_id));
		mbuf1 = (uint64_t *)((uintptr_t)mbuf1 +
				     offsetof(struct rte_mempool, pool_id));
		mbuf2 = (uint64_t *)((uintptr_t)mbuf2 +
				     offsetof(struct rte_mempool, pool_id));
		mbuf3 = (uint64_t *)((uintptr_t)mbuf3 +
				     offsetof(struct rte_mempool, pool_id));

		if ((flags & NIX_TX_OFFLOAD_L3_L4_CSUM_F) &&
		    !(flags & NIX_TX_OFFLOAD_OL3_OL4_CSUM_F)) {
			/*
			 * Lookup table to translate ol_flags to
			 * il3/il4 types. But we still use ol3/ol4 types in
			 * senddesc_w1 as only one header processing is enabled.
			 */
			const uint8x16_t tbl = {
				/* [0-15] = il4type:il3type */
				0x04, /* none (IPv6 assumed) */
				0x14, /* PKT_TX_TCP_CKSUM (IPv6 assumed) */
				0x24, /* PKT_TX_SCTP_CKSUM (IPv6 assumed) */
				0x34, /* PKT_TX_UDP_CKSUM (IPv6 assumed) */
				0x03, /* PKT_TX_IP_CKSUM */
				0x13, /* PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM */
				0x23, /* PKT_TX_IP_CKSUM | PKT_TX_SCTP_CKSUM */
				0x33, /* PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM */
				0x02, /* PKT_TX_IPV4  */
				0x12, /* PKT_TX_IPV4 | PKT_TX_TCP_CKSUM */
				0x22, /* PKT_TX_IPV4 | PKT_TX_SCTP_CKSUM */
				0x32, /* PKT_TX_IPV4 | PKT_TX_UDP_CKSUM */
				0x03, /* PKT_TX_IPV4 | PKT_TX_IP_CKSUM */
				0x13, /* PKT_TX_IPV4 | PKT_TX_IP_CKSUM |
				       * PKT_TX_TCP_CKSUM
				       */
				0x23, /* PKT_TX_IPV4 | PKT_TX_IP_CKSUM |
				       * PKT_TX_SCTP_CKSUM
				       */
				0x33, /* PKT_TX_IPV4 | PKT_TX_IP_CKSUM |
				       * PKT_TX_UDP_CKSUM
				       */
			};

			/* Extract olflags to translate to iltypes */
			xtmp128 = vzip1q_u64(len_olflags0, len_olflags1);
			ytmp128 = vzip1q_u64(len_olflags2, len_olflags3);

			/*
			 * E(47):L3_LEN(9):L2_LEN(7+z)
			 * E(47):L3_LEN(9):L2_LEN(7+z)
			 */
			senddesc01_w1 = vshlq_n_u64(senddesc01_w1, 1);
			senddesc23_w1 = vshlq_n_u64(senddesc23_w1, 1);

			/* Move OLFLAGS bits 55:52 to 51:48
			 * with zeros preprended on the byte and rest
			 * don't care
			 */
			xtmp128 = vshrq_n_u8(xtmp128, 4);
			ytmp128 = vshrq_n_u8(ytmp128, 4);
			/*
			 * E(48):L3_LEN(8):L2_LEN(z+7)
			 * E(48):L3_LEN(8):L2_LEN(z+7)
			 */
			const int8x16_t tshft3 = {
				-1, 0, 8, 8, 8, 8, 8, 8,
				-1, 0, 8, 8, 8, 8, 8, 8,
			};

			senddesc01_w1 = vshlq_u8(senddesc01_w1, tshft3);
			senddesc23_w1 = vshlq_u8(senddesc23_w1, tshft3);

			/* Do the lookup */
			ltypes01 = vqtbl1q_u8(tbl, xtmp128);
			ltypes23 = vqtbl1q_u8(tbl, ytmp128);

			/* Pick only relevant fields i.e Bit 48:55 of iltype
			 * and place it in ol3/ol4type of senddesc_w1
			 */
			const uint8x16_t shuf_mask0 = {
				0xFF, 0xFF, 0xFF, 0xFF, 0x6, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xE, 0xFF, 0xFF, 0xFF,
			};

			ltypes01 = vqtbl1q_u8(ltypes01, shuf_mask0);
			ltypes23 = vqtbl1q_u8(ltypes23, shuf_mask0);

			/* Prepare ol4ptr, ol3ptr from ol3len, ol2len.
			 * a [E(32):E(16):OL3(8):OL2(8)]
			 * a = a + (a << 8)
			 * a [E(32):E(16):(OL3+OL2):OL2]
			 * => E(32):E(16)::OL4PTR(8):OL3PTR(8)
			 */
			senddesc01_w1 = vaddq_u8(senddesc01_w1,
						 vshlq_n_u16(senddesc01_w1, 8));
			senddesc23_w1 = vaddq_u8(senddesc23_w1,
						 vshlq_n_u16(senddesc23_w1, 8));

			/* Move ltypes to senddesc*_w1 */
			senddesc01_w1 = vorrq_u64(senddesc01_w1, ltypes01);
			senddesc23_w1 = vorrq_u64(senddesc23_w1, ltypes23);
		} else if (!(flags & NIX_TX_OFFLOAD_L3_L4_CSUM_F) &&
			   (flags & NIX_TX_OFFLOAD_OL3_OL4_CSUM_F)) {
			/*
			 * Lookup table to translate ol_flags to
			 * ol3/ol4 types.
			 */

			const uint8x16_t tbl = {
				/* [0-15] = ol4type:ol3type */
				0x00, /* none */
				0x03, /* OUTER_IP_CKSUM */
				0x02, /* OUTER_IPV4 */
				0x03, /* OUTER_IPV4 | OUTER_IP_CKSUM */
				0x04, /* OUTER_IPV6 */
				0x00, /* OUTER_IPV6 | OUTER_IP_CKSUM */
				0x00, /* OUTER_IPV6 | OUTER_IPV4 */
				0x00, /* OUTER_IPV6 | OUTER_IPV4 |
				       * OUTER_IP_CKSUM
				       */
				0x00, /* OUTER_UDP_CKSUM */
				0x33, /* OUTER_UDP_CKSUM | OUTER_IP_CKSUM */
				0x32, /* OUTER_UDP_CKSUM | OUTER_IPV4 */
				0x33, /* OUTER_UDP_CKSUM | OUTER_IPV4 |
				       * OUTER_IP_CKSUM
				       */
				0x34, /* OUTER_UDP_CKSUM | OUTER_IPV6 */
				0x00, /* OUTER_UDP_CKSUM | OUTER_IPV6 |
				       * OUTER_IP_CKSUM
				       */
				0x00, /* OUTER_UDP_CKSUM | OUTER_IPV6 |
				       * OUTER_IPV4
				       */
				0x00, /* OUTER_UDP_CKSUM | OUTER_IPV6 |
				       * OUTER_IPV4 | OUTER_IP_CKSUM
				       */
			};

			/* Extract olflags to translate to iltypes */
			xtmp128 = vzip1q_u64(len_olflags0, len_olflags1);
			ytmp128 = vzip1q_u64(len_olflags2, len_olflags3);

			/*
			 * E(47):OL3_LEN(9):OL2_LEN(7+z)
			 * E(47):OL3_LEN(9):OL2_LEN(7+z)
			 */
			const uint8x16_t shuf_mask5 = {
				0x6, 0x5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xE, 0xD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			};
			senddesc01_w1 = vqtbl1q_u8(senddesc01_w1, shuf_mask5);
			senddesc23_w1 = vqtbl1q_u8(senddesc23_w1, shuf_mask5);

			/* Extract outer ol flags only */
			const uint64x2_t o_cksum_mask = {
				0x1C00020000000000,
				0x1C00020000000000,
			};

			xtmp128 = vandq_u64(xtmp128, o_cksum_mask);
			ytmp128 = vandq_u64(ytmp128, o_cksum_mask);

			/* Extract OUTER_UDP_CKSUM bit 41 and
			 * move it to bit 61
			 */

			xtmp128 = xtmp128 | vshlq_n_u64(xtmp128, 20);
			ytmp128 = ytmp128 | vshlq_n_u64(ytmp128, 20);

			/* Shift oltype by 2 to start nibble from BIT(56)
			 * instead of BIT(58)
			 */
			xtmp128 = vshrq_n_u8(xtmp128, 2);
			ytmp128 = vshrq_n_u8(ytmp128, 2);
			/*
			 * E(48):L3_LEN(8):L2_LEN(z+7)
			 * E(48):L3_LEN(8):L2_LEN(z+7)
			 */
			const int8x16_t tshft3 = {
				-1, 0, 8, 8, 8, 8, 8, 8,
				-1, 0, 8, 8, 8, 8, 8, 8,
			};

			senddesc01_w1 = vshlq_u8(senddesc01_w1, tshft3);
			senddesc23_w1 = vshlq_u8(senddesc23_w1, tshft3);

			/* Do the lookup */
			ltypes01 = vqtbl1q_u8(tbl, xtmp128);
			ltypes23 = vqtbl1q_u8(tbl, ytmp128);

			/* Pick only relevant fields i.e Bit 56:63 of oltype
			 * and place it in ol3/ol4type of senddesc_w1
			 */
			const uint8x16_t shuf_mask0 = {
				0xFF, 0xFF, 0xFF, 0xFF, 0x7, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xF, 0xFF, 0xFF, 0xFF,
			};

			ltypes01 = vqtbl1q_u8(ltypes01, shuf_mask0);
			ltypes23 = vqtbl1q_u8(ltypes23, shuf_mask0);

			/* Prepare ol4ptr, ol3ptr from ol3len, ol2len.
			 * a [E(32):E(16):OL3(8):OL2(8)]
			 * a = a + (a << 8)
			 * a [E(32):E(16):(OL3+OL2):OL2]
			 * => E(32):E(16)::OL4PTR(8):OL3PTR(8)
			 */
			senddesc01_w1 = vaddq_u8(senddesc01_w1,
						 vshlq_n_u16(senddesc01_w1, 8));
			senddesc23_w1 = vaddq_u8(senddesc23_w1,
						 vshlq_n_u16(senddesc23_w1, 8));

			/* Move ltypes to senddesc*_w1 */
			senddesc01_w1 = vorrq_u64(senddesc01_w1, ltypes01);
			senddesc23_w1 = vorrq_u64(senddesc23_w1, ltypes23);
		} else if ((flags & NIX_TX_OFFLOAD_L3_L4_CSUM_F) &&
			   (flags & NIX_TX_OFFLOAD_OL3_OL4_CSUM_F)) {
			/* Lookup table to translate ol_flags to
			 * ol4type, ol3type, il4type, il3type of senddesc_w1
			 */
			const uint8x16x2_t tbl = {{
				{
					/* [0-15] = il4type:il3type */
					0x04, /* none (IPv6) */
					0x14, /* PKT_TX_TCP_CKSUM (IPv6) */
					0x24, /* PKT_TX_SCTP_CKSUM (IPv6) */
					0x34, /* PKT_TX_UDP_CKSUM (IPv6) */
					0x03, /* PKT_TX_IP_CKSUM */
					0x13, /* PKT_TX_IP_CKSUM |
					       * PKT_TX_TCP_CKSUM
					       */
					0x23, /* PKT_TX_IP_CKSUM |
					       * PKT_TX_SCTP_CKSUM
					       */
					0x33, /* PKT_TX_IP_CKSUM |
					       * PKT_TX_UDP_CKSUM
					       */
					0x02, /* PKT_TX_IPV4 */
					0x12, /* PKT_TX_IPV4 |
					       * PKT_TX_TCP_CKSUM
					       */
					0x22, /* PKT_TX_IPV4 |
					       * PKT_TX_SCTP_CKSUM
					       */
					0x32, /* PKT_TX_IPV4 |
					       * PKT_TX_UDP_CKSUM
					       */
					0x03, /* PKT_TX_IPV4 |
					       * PKT_TX_IP_CKSUM
					       */
					0x13, /* PKT_TX_IPV4 | PKT_TX_IP_CKSUM |
					       * PKT_TX_TCP_CKSUM
					       */
					0x23, /* PKT_TX_IPV4 | PKT_TX_IP_CKSUM |
					       * PKT_TX_SCTP_CKSUM
					       */
					0x33, /* PKT_TX_IPV4 | PKT_TX_IP_CKSUM |
					       * PKT_TX_UDP_CKSUM
					       */
				},

				{
					/* [16-31] = ol4type:ol3type */
					0x00, /* none */
					0x03, /* OUTER_IP_CKSUM */
					0x02, /* OUTER_IPV4 */
					0x03, /* OUTER_IPV4 | OUTER_IP_CKSUM */
					0x04, /* OUTER_IPV6 */
					0x00, /* OUTER_IPV6 | OUTER_IP_CKSUM */
					0x00, /* OUTER_IPV6 | OUTER_IPV4 */
					0x00, /* OUTER_IPV6 | OUTER_IPV4 |
					       * OUTER_IP_CKSUM
					       */
					0x00, /* OUTER_UDP_CKSUM */
					0x33, /* OUTER_UDP_CKSUM |
					       * OUTER_IP_CKSUM
					       */
					0x32, /* OUTER_UDP_CKSUM |
					       * OUTER_IPV4
					       */
					0x33, /* OUTER_UDP_CKSUM |
					       * OUTER_IPV4 | OUTER_IP_CKSUM
					       */
					0x34, /* OUTER_UDP_CKSUM |
					       * OUTER_IPV6
					       */
					0x00, /* OUTER_UDP_CKSUM | OUTER_IPV6 |
					       * OUTER_IP_CKSUM
					       */
					0x00, /* OUTER_UDP_CKSUM | OUTER_IPV6 |
					       * OUTER_IPV4
					       */
					0x00, /* OUTER_UDP_CKSUM | OUTER_IPV6 |
					       * OUTER_IPV4 | OUTER_IP_CKSUM
					       */
				},
			}};

			/* Extract olflags to translate to oltype & iltype */
			xtmp128 = vzip1q_u64(len_olflags0, len_olflags1);
			ytmp128 = vzip1q_u64(len_olflags2, len_olflags3);

			/*
			 * E(8):OL2_LN(7):OL3_LN(9):E(23):L3_LN(9):L2_LN(7+z)
			 * E(8):OL2_LN(7):OL3_LN(9):E(23):L3_LN(9):L2_LN(7+z)
			 */
			const uint32x4_t tshft_4 = {
				1,
				0,
				1,
				0,
			};
			senddesc01_w1 = vshlq_u32(senddesc01_w1, tshft_4);
			senddesc23_w1 = vshlq_u32(senddesc23_w1, tshft_4);

			/*
			 * E(32):L3_LEN(8):L2_LEN(7+Z):OL3_LEN(8):OL2_LEN(7+Z)
			 * E(32):L3_LEN(8):L2_LEN(7+Z):OL3_LEN(8):OL2_LEN(7+Z)
			 */
			const uint8x16_t shuf_mask5 = {
				0x6, 0x5, 0x0, 0x1, 0xFF, 0xFF, 0xFF, 0xFF,
				0xE, 0xD, 0x8, 0x9, 0xFF, 0xFF, 0xFF, 0xFF,
			};
			senddesc01_w1 = vqtbl1q_u8(senddesc01_w1, shuf_mask5);
			senddesc23_w1 = vqtbl1q_u8(senddesc23_w1, shuf_mask5);

			/* Extract outer and inner header ol_flags */
			const uint64x2_t oi_cksum_mask = {
				0x1CF0020000000000,
				0x1CF0020000000000,
			};

			xtmp128 = vandq_u64(xtmp128, oi_cksum_mask);
			ytmp128 = vandq_u64(ytmp128, oi_cksum_mask);

			/* Extract OUTER_UDP_CKSUM bit 41 and
			 * move it to bit 61
			 */

			xtmp128 = xtmp128 | vshlq_n_u64(xtmp128, 20);
			ytmp128 = ytmp128 | vshlq_n_u64(ytmp128, 20);

			/* Shift right oltype by 2 and iltype by 4
			 * to start oltype nibble from BIT(58)
			 * instead of BIT(56) and iltype nibble from BIT(48)
			 * instead of BIT(52).
			 */
			const int8x16_t tshft5 = {
				8, 8, 8, 8, 8, 8, -4, -2,
				8, 8, 8, 8, 8, 8, -4, -2,
			};

			xtmp128 = vshlq_u8(xtmp128, tshft5);
			ytmp128 = vshlq_u8(ytmp128, tshft5);
			/*
			 * E(32):L3_LEN(8):L2_LEN(8):OL3_LEN(8):OL2_LEN(8)
			 * E(32):L3_LEN(8):L2_LEN(8):OL3_LEN(8):OL2_LEN(8)
			 */
			const int8x16_t tshft3 = {
				-1, 0, -1, 0, 0, 0, 0, 0,
				-1, 0, -1, 0, 0, 0, 0, 0,
			};

			senddesc01_w1 = vshlq_u8(senddesc01_w1, tshft3);
			senddesc23_w1 = vshlq_u8(senddesc23_w1, tshft3);

			/* Mark Bit(4) of oltype */
			const uint64x2_t oi_cksum_mask2 = {
				0x1000000000000000,
				0x1000000000000000,
			};

			xtmp128 = vorrq_u64(xtmp128, oi_cksum_mask2);
			ytmp128 = vorrq_u64(ytmp128, oi_cksum_mask2);

			/* Do the lookup */
			ltypes01 = vqtbl2q_u8(tbl, xtmp128);
			ltypes23 = vqtbl2q_u8(tbl, ytmp128);

			/* Pick only relevant fields i.e Bit 48:55 of iltype and
			 * Bit 56:63 of oltype and place it in corresponding
			 * place in senddesc_w1.
			 */
			const uint8x16_t shuf_mask0 = {
				0xFF, 0xFF, 0xFF, 0xFF, 0x7, 0x6, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xF, 0xE, 0xFF, 0xFF,
			};

			ltypes01 = vqtbl1q_u8(ltypes01, shuf_mask0);
			ltypes23 = vqtbl1q_u8(ltypes23, shuf_mask0);

			/* Prepare l4ptr, l3ptr, ol4ptr, ol3ptr from
			 * l3len, l2len, ol3len, ol2len.
			 * a [E(32):L3(8):L2(8):OL3(8):OL2(8)]
			 * a = a + (a << 8)
			 * a [E:(L3+L2):(L2+OL3):(OL3+OL2):OL2]
			 * a = a + (a << 16)
			 * a [E:(L3+L2+OL3+OL2):(L2+OL3+OL2):(OL3+OL2):OL2]
			 * => E(32):IL4PTR(8):IL3PTR(8):OL4PTR(8):OL3PTR(8)
			 */
			senddesc01_w1 = vaddq_u8(senddesc01_w1,
						 vshlq_n_u32(senddesc01_w1, 8));
			senddesc23_w1 = vaddq_u8(senddesc23_w1,
						 vshlq_n_u32(senddesc23_w1, 8));

			/* Continue preparing l4ptr, l3ptr, ol4ptr, ol3ptr */
			senddesc01_w1 = vaddq_u8(
				senddesc01_w1, vshlq_n_u32(senddesc01_w1, 16));
			senddesc23_w1 = vaddq_u8(
				senddesc23_w1, vshlq_n_u32(senddesc23_w1, 16));

			/* Move ltypes to senddesc*_w1 */
			senddesc01_w1 = vorrq_u64(senddesc01_w1, ltypes01);
			senddesc23_w1 = vorrq_u64(senddesc23_w1, ltypes23);
		}

		xmask01 = vdupq_n_u64(0);
		xmask23 = xmask01;
		asm volatile("LD1 {%[a].H}[0],[%[in]]\n\t"
			     : [a] "+w"(xmask01)
			     : [in] "r"(mbuf0)
			     : "memory");

		asm volatile("LD1 {%[a].H}[4],[%[in]]\n\t"
			     : [a] "+w"(xmask01)
			     : [in] "r"(mbuf1)
			     : "memory");

		asm volatile("LD1 {%[b].H}[0],[%[in]]\n\t"
			     : [b] "+w"(xmask23)
			     : [in] "r"(mbuf2)
			     : "memory");

		asm volatile("LD1 {%[b].H}[4],[%[in]]\n\t"
			     : [b] "+w"(xmask23)
			     : [in] "r"(mbuf3)
			     : "memory");
		xmask01 = vshlq_n_u64(xmask01, 20);
		xmask23 = vshlq_n_u64(xmask23, 20);

		senddesc01_w0 = vorrq_u64(senddesc01_w0, xmask01);
		senddesc23_w0 = vorrq_u64(senddesc23_w0, xmask23);

		if (flags & NIX_TX_OFFLOAD_VLAN_QINQ_F) {
			/* Tx ol_flag for vlan. */
			const uint64x2_t olv = {PKT_TX_VLAN, PKT_TX_VLAN};
			/* Bit enable for VLAN1 */
			const uint64x2_t mlv = {BIT_ULL(49), BIT_ULL(49)};
			/* Tx ol_flag for QnQ. */
			const uint64x2_t olq = {PKT_TX_QINQ, PKT_TX_QINQ};
			/* Bit enable for VLAN0 */
			const uint64x2_t mlq = {BIT_ULL(48), BIT_ULL(48)};
			/* Load vlan values from packet. outer is VLAN 0 */
			uint64x2_t ext01 = {
				((uint32_t)tx_pkts[0]->vlan_tci_outer) << 8 |
					((uint64_t)tx_pkts[0]->vlan_tci) << 32,
				((uint32_t)tx_pkts[1]->vlan_tci_outer) << 8 |
					((uint64_t)tx_pkts[1]->vlan_tci) << 32,
			};
			uint64x2_t ext23 = {
				((uint32_t)tx_pkts[2]->vlan_tci_outer) << 8 |
					((uint64_t)tx_pkts[2]->vlan_tci) << 32,
				((uint32_t)tx_pkts[3]->vlan_tci_outer) << 8 |
					((uint64_t)tx_pkts[3]->vlan_tci) << 32,
			};

			/* Get ol_flags of the packets. */
			xtmp128 = vzip1q_u64(len_olflags0, len_olflags1);
			ytmp128 = vzip1q_u64(len_olflags2, len_olflags3);

			/* ORR vlan outer/inner values into cmd. */
			sendext01_w1 = vorrq_u64(sendext01_w1, ext01);
			sendext23_w1 = vorrq_u64(sendext23_w1, ext23);

			/* Test for offload enable bits and generate masks. */
			xtmp128 = vorrq_u64(vandq_u64(vtstq_u64(xtmp128, olv),
						      mlv),
					    vandq_u64(vtstq_u64(xtmp128, olq),
						      mlq));
			ytmp128 = vorrq_u64(vandq_u64(vtstq_u64(ytmp128, olv),
						      mlv),
					    vandq_u64(vtstq_u64(ytmp128, olq),
						      mlq));

			/* Set vlan enable bits into cmd based on mask. */
			sendext01_w1 = vorrq_u64(sendext01_w1, xtmp128);
			sendext23_w1 = vorrq_u64(sendext23_w1, ytmp128);
		}

		if (flags & NIX_TX_OFFLOAD_TSTAMP_F) {
			/* Tx ol_flag for timestam. */
			const uint64x2_t olf = {PKT_TX_IEEE1588_TMST,
						PKT_TX_IEEE1588_TMST};
			/* Set send mem alg to SUB. */
			const uint64x2_t alg = {BIT_ULL(59), BIT_ULL(59)};
			/* Increment send mem address by 8. */
			const uint64x2_t addr = {0x8, 0x8};

			xtmp128 = vzip1q_u64(len_olflags0, len_olflags1);
			ytmp128 = vzip1q_u64(len_olflags2, len_olflags3);

			/* Check if timestamp is requested and generate inverted
			 * mask as we need not make any changes to default cmd
			 * value.
			 */
			xtmp128 = vmvnq_u32(vtstq_u64(olf, xtmp128));
			ytmp128 = vmvnq_u32(vtstq_u64(olf, ytmp128));

			/* Change send mem address to an 8 byte offset when
			 * TSTMP is disabled.
			 */
			sendmem01_w1 = vaddq_u64(sendmem01_w1,
						 vandq_u64(xtmp128, addr));
			sendmem23_w1 = vaddq_u64(sendmem23_w1,
						 vandq_u64(ytmp128, addr));
			/* Change send mem alg to SUB when TSTMP is disabled. */
			sendmem01_w0 = vorrq_u64(sendmem01_w0,
						 vandq_u64(xtmp128, alg));
			sendmem23_w0 = vorrq_u64(sendmem23_w0,
						 vandq_u64(ytmp128, alg));

			cmd3[0] = vzip1q_u64(sendmem01_w0, sendmem01_w1);
			cmd3[1] = vzip2q_u64(sendmem01_w0, sendmem01_w1);
			cmd3[2] = vzip1q_u64(sendmem23_w0, sendmem23_w1);
			cmd3[3] = vzip2q_u64(sendmem23_w0, sendmem23_w1);
		}

		if (flags & NIX_TX_OFFLOAD_TSO_F) {
			const uint64_t lso_fmt = txq->lso_tun_fmt;
			uint64_t sx_w0[NIX_DESCS_PER_LOOP];
			uint64_t sd_w1[NIX_DESCS_PER_LOOP];

			/* Extract SD W1 as we need to set L4 types. */
			vst1q_u64(sd_w1, senddesc01_w1);
			vst1q_u64(sd_w1 + 2, senddesc23_w1);

			/* Extract SX W0 as we need to set LSO fields. */
			vst1q_u64(sx_w0, sendext01_w0);
			vst1q_u64(sx_w0 + 2, sendext23_w0);

			/* Extract ol_flags. */
			xtmp128 = vzip1q_u64(len_olflags0, len_olflags1);
			ytmp128 = vzip1q_u64(len_olflags2, len_olflags3);

			/* Prepare individual mbufs. */
			cn10k_nix_prepare_tso(tx_pkts[0],
				(union nix_send_hdr_w1_u *)&sd_w1[0],
				(union nix_send_ext_w0_u *)&sx_w0[0],
				vgetq_lane_u64(xtmp128, 0), flags, lso_fmt);

			cn10k_nix_prepare_tso(tx_pkts[1],
				(union nix_send_hdr_w1_u *)&sd_w1[1],
				(union nix_send_ext_w0_u *)&sx_w0[1],
				vgetq_lane_u64(xtmp128, 1), flags, lso_fmt);

			cn10k_nix_prepare_tso(tx_pkts[2],
				(union nix_send_hdr_w1_u *)&sd_w1[2],
				(union nix_send_ext_w0_u *)&sx_w0[2],
				vgetq_lane_u64(ytmp128, 0), flags, lso_fmt);

			cn10k_nix_prepare_tso(tx_pkts[3],
				(union nix_send_hdr_w1_u *)&sd_w1[3],
				(union nix_send_ext_w0_u *)&sx_w0[3],
				vgetq_lane_u64(ytmp128, 1), flags, lso_fmt);

			senddesc01_w1 = vld1q_u64(sd_w1);
			senddesc23_w1 = vld1q_u64(sd_w1 + 2);

			sendext01_w0 = vld1q_u64(sx_w0);
			sendext23_w0 = vld1q_u64(sx_w0 + 2);
		}

		if (flags & NIX_TX_OFFLOAD_MBUF_NOFF_F) {
			/* Set don't free bit if reference count > 1 */
			xmask01 = vdupq_n_u64(0);
			xmask23 = xmask01;

			/* Move mbufs to iova */
			mbuf0 = (uint64_t *)tx_pkts[0];
			mbuf1 = (uint64_t *)tx_pkts[1];
			mbuf2 = (uint64_t *)tx_pkts[2];
			mbuf3 = (uint64_t *)tx_pkts[3];

			if (cnxk_nix_prefree_seg((struct rte_mbuf *)mbuf0))
				vsetq_lane_u64(0x80000, xmask01, 0);
			else
				__mempool_check_cookies(
					((struct rte_mbuf *)mbuf0)->pool,
					(void **)&mbuf0, 1, 0);

			if (cnxk_nix_prefree_seg((struct rte_mbuf *)mbuf1))
				vsetq_lane_u64(0x80000, xmask01, 1);
			else
				__mempool_check_cookies(
					((struct rte_mbuf *)mbuf1)->pool,
					(void **)&mbuf1, 1, 0);

			if (cnxk_nix_prefree_seg((struct rte_mbuf *)mbuf2))
				vsetq_lane_u64(0x80000, xmask23, 0);
			else
				__mempool_check_cookies(
					((struct rte_mbuf *)mbuf2)->pool,
					(void **)&mbuf2, 1, 0);

			if (cnxk_nix_prefree_seg((struct rte_mbuf *)mbuf3))
				vsetq_lane_u64(0x80000, xmask23, 1);
			else
				__mempool_check_cookies(
					((struct rte_mbuf *)mbuf3)->pool,
					(void **)&mbuf3, 1, 0);
			senddesc01_w0 = vorrq_u64(senddesc01_w0, xmask01);
			senddesc23_w0 = vorrq_u64(senddesc23_w0, xmask23);
		} else {
			/* Move mbufs to iova */
			mbuf0 = (uint64_t *)tx_pkts[0];
			mbuf1 = (uint64_t *)tx_pkts[1];
			mbuf2 = (uint64_t *)tx_pkts[2];
			mbuf3 = (uint64_t *)tx_pkts[3];

			/* Mark mempool object as "put" since
			 * it is freed by NIX
			 */
			__mempool_check_cookies(
				((struct rte_mbuf *)mbuf0)->pool,
				(void **)&mbuf0, 1, 0);

			__mempool_check_cookies(
				((struct rte_mbuf *)mbuf1)->pool,
				(void **)&mbuf1, 1, 0);

			__mempool_check_cookies(
				((struct rte_mbuf *)mbuf2)->pool,
				(void **)&mbuf2, 1, 0);

			__mempool_check_cookies(
				((struct rte_mbuf *)mbuf3)->pool,
				(void **)&mbuf3, 1, 0);
		}

		/* Create 4W cmd for 4 mbufs (sendhdr, sgdesc) */
		cmd0[0] = vzip1q_u64(senddesc01_w0, senddesc01_w1);
		cmd0[1] = vzip2q_u64(senddesc01_w0, senddesc01_w1);
		cmd0[2] = vzip1q_u64(senddesc23_w0, senddesc23_w1);
		cmd0[3] = vzip2q_u64(senddesc23_w0, senddesc23_w1);

		cmd1[0] = vzip1q_u64(sgdesc01_w0, sgdesc01_w1);
		cmd1[1] = vzip2q_u64(sgdesc01_w0, sgdesc01_w1);
		cmd1[2] = vzip1q_u64(sgdesc23_w0, sgdesc23_w1);
		cmd1[3] = vzip2q_u64(sgdesc23_w0, sgdesc23_w1);

		if (flags & NIX_TX_NEED_EXT_HDR) {
			cmd2[0] = vzip1q_u64(sendext01_w0, sendext01_w1);
			cmd2[1] = vzip2q_u64(sendext01_w0, sendext01_w1);
			cmd2[2] = vzip1q_u64(sendext23_w0, sendext23_w1);
			cmd2[3] = vzip2q_u64(sendext23_w0, sendext23_w1);
		}

		if (flags & NIX_TX_NEED_EXT_HDR) {
			/* Store the prepared send desc to LMT lines */
			if (flags & NIX_TX_OFFLOAD_TSTAMP_F) {
				vst1q_u64(LMT_OFF(laddr, lnum, 0), cmd0[0]);
				vst1q_u64(LMT_OFF(laddr, lnum, 16), cmd2[0]);
				vst1q_u64(LMT_OFF(laddr, lnum, 32), cmd1[0]);
				vst1q_u64(LMT_OFF(laddr, lnum, 48), cmd3[0]);
				vst1q_u64(LMT_OFF(laddr, lnum, 64), cmd0[1]);
				vst1q_u64(LMT_OFF(laddr, lnum, 80), cmd2[1]);
				vst1q_u64(LMT_OFF(laddr, lnum, 96), cmd1[1]);
				vst1q_u64(LMT_OFF(laddr, lnum, 112), cmd3[1]);
				lnum += 1;
				vst1q_u64(LMT_OFF(laddr, lnum, 0), cmd0[2]);
				vst1q_u64(LMT_OFF(laddr, lnum, 16), cmd2[2]);
				vst1q_u64(LMT_OFF(laddr, lnum, 32), cmd1[2]);
				vst1q_u64(LMT_OFF(laddr, lnum, 48), cmd3[2]);
				vst1q_u64(LMT_OFF(laddr, lnum, 64), cmd0[3]);
				vst1q_u64(LMT_OFF(laddr, lnum, 80), cmd2[3]);
				vst1q_u64(LMT_OFF(laddr, lnum, 96), cmd1[3]);
				vst1q_u64(LMT_OFF(laddr, lnum, 112), cmd3[3]);
			} else {
				vst1q_u64(LMT_OFF(laddr, lnum, 0), cmd0[0]);
				vst1q_u64(LMT_OFF(laddr, lnum, 16), cmd2[0]);
				vst1q_u64(LMT_OFF(laddr, lnum, 32), cmd1[0]);
				vst1q_u64(LMT_OFF(laddr, lnum, 48), cmd0[1]);
				vst1q_u64(LMT_OFF(laddr, lnum, 64), cmd2[1]);
				vst1q_u64(LMT_OFF(laddr, lnum, 80), cmd1[1]);
				lnum += 1;
				vst1q_u64(LMT_OFF(laddr, lnum, 0), cmd0[2]);
				vst1q_u64(LMT_OFF(laddr, lnum, 16), cmd2[2]);
				vst1q_u64(LMT_OFF(laddr, lnum, 32), cmd1[2]);
				vst1q_u64(LMT_OFF(laddr, lnum, 48), cmd0[3]);
				vst1q_u64(LMT_OFF(laddr, lnum, 64), cmd2[3]);
				vst1q_u64(LMT_OFF(laddr, lnum, 80), cmd1[3]);
			}
			lnum += 1;
		} else {
			/* Store the prepared send desc to LMT lines */
			vst1q_u64(LMT_OFF(laddr, lnum, 0), cmd0[0]);
			vst1q_u64(LMT_OFF(laddr, lnum, 16), cmd1[0]);
			vst1q_u64(LMT_OFF(laddr, lnum, 32), cmd0[1]);
			vst1q_u64(LMT_OFF(laddr, lnum, 48), cmd1[1]);
			vst1q_u64(LMT_OFF(laddr, lnum, 64), cmd0[2]);
			vst1q_u64(LMT_OFF(laddr, lnum, 80), cmd1[2]);
			vst1q_u64(LMT_OFF(laddr, lnum, 96), cmd0[3]);
			vst1q_u64(LMT_OFF(laddr, lnum, 112), cmd1[3]);
			lnum += 1;
		}

		tx_pkts = tx_pkts + NIX_DESCS_PER_LOOP;
	}

	/* Trigger LMTST */
	if (lnum > 16) {
		data = cn10k_nix_tx_steor_vec_data(flags);
		pa = io_addr | (data & 0x7) << 4;
		data &= ~0x7ULL;
		data |= (15ULL << 12);
		data |= (uint64_t)lmt_id;

		/* STEOR0 */
		roc_lmt_submit_steorl(data, pa);

		data = cn10k_nix_tx_steor_vec_data(flags);
		pa = io_addr | (data & 0x7) << 4;
		data &= ~0x7ULL;
		data |= ((uint64_t)(lnum - 17)) << 12;
		data |= (uint64_t)(lmt_id + 16);

		/* STEOR1 */
		roc_lmt_submit_steorl(data, pa);
	} else if (lnum) {
		data = cn10k_nix_tx_steor_vec_data(flags);
		pa = io_addr | (data & 0x7) << 4;
		data &= ~0x7ULL;
		data |= ((uint64_t)(lnum - 1)) << 12;
		data |= lmt_id;

		/* STEOR0 */
		roc_lmt_submit_steorl(data, pa);
	}

	left -= burst;
	rte_io_wmb();
	if (left)
		goto again;

	if (unlikely(scalar))
		pkts += cn10k_nix_xmit_pkts(tx_queue, tx_pkts, scalar, cmd,
					    flags);

	return pkts;
}

#else
static __rte_always_inline uint16_t
cn10k_nix_xmit_pkts_vector(void *tx_queue, struct rte_mbuf **tx_pkts,
			   uint16_t pkts, uint64_t *cmd, const uint16_t flags)
{
	RTE_SET_USED(tx_queue);
	RTE_SET_USED(tx_pkts);
	RTE_SET_USED(pkts);
	RTE_SET_USED(cmd);
	RTE_SET_USED(flags);
	return 0;
}
#endif

#define L3L4CSUM_F   NIX_TX_OFFLOAD_L3_L4_CSUM_F
#define OL3OL4CSUM_F NIX_TX_OFFLOAD_OL3_OL4_CSUM_F
#define VLAN_F	     NIX_TX_OFFLOAD_VLAN_QINQ_F
#define NOFF_F	     NIX_TX_OFFLOAD_MBUF_NOFF_F
#define TSO_F	     NIX_TX_OFFLOAD_TSO_F
#define TSP_F	     NIX_TX_OFFLOAD_TSTAMP_F

/* [TSP] [TSO] [NOFF] [VLAN] [OL3OL4CSUM] [L3L4CSUM] */
#define NIX_TX_FASTPATH_MODES						\
T(no_offload,				0, 0, 0, 0, 0, 0,	4,	\
		NIX_TX_OFFLOAD_NONE)					\
T(l3l4csum,				0, 0, 0, 0, 0, 1,	4,	\
		L3L4CSUM_F)						\
T(ol3ol4csum,				0, 0, 0, 0, 1, 0,	4,	\
		OL3OL4CSUM_F)						\
T(ol3ol4csum_l3l4csum,			0, 0, 0, 0, 1, 1,	4,	\
		OL3OL4CSUM_F | L3L4CSUM_F)				\
T(vlan,					0, 0, 0, 1, 0, 0,	6,	\
		VLAN_F)							\
T(vlan_l3l4csum,			0, 0, 0, 1, 0, 1,	6,	\
		VLAN_F | L3L4CSUM_F)					\
T(vlan_ol3ol4csum,			0, 0, 0, 1, 1, 0,	6,	\
		VLAN_F | OL3OL4CSUM_F)					\
T(vlan_ol3ol4csum_l3l4csum,		0, 0, 0, 1, 1, 1,	6,	\
		VLAN_F | OL3OL4CSUM_F |	L3L4CSUM_F)			\
T(noff,					0, 0, 1, 0, 0, 0,	4,	\
		NOFF_F)							\
T(noff_l3l4csum,			0, 0, 1, 0, 0, 1,	4,	\
		NOFF_F | L3L4CSUM_F)					\
T(noff_ol3ol4csum,			0, 0, 1, 0, 1, 0,	4,	\
		NOFF_F | OL3OL4CSUM_F)					\
T(noff_ol3ol4csum_l3l4csum,		0, 0, 1, 0, 1, 1,	4,	\
		NOFF_F | OL3OL4CSUM_F |	L3L4CSUM_F)			\
T(noff_vlan,				0, 0, 1, 1, 0, 0,	6,	\
		NOFF_F | VLAN_F)					\
T(noff_vlan_l3l4csum,			0, 0, 1, 1, 0, 1,	6,	\
		NOFF_F | VLAN_F | L3L4CSUM_F)				\
T(noff_vlan_ol3ol4csum,			0, 0, 1, 1, 1, 0,	6,	\
		NOFF_F | VLAN_F | OL3OL4CSUM_F)				\
T(noff_vlan_ol3ol4csum_l3l4csum,	0, 0, 1, 1, 1, 1,	6,	\
		NOFF_F | VLAN_F | OL3OL4CSUM_F | L3L4CSUM_F)		\
T(tso,					0, 1, 0, 0, 0, 0,	6,	\
		TSO_F)							\
T(tso_l3l4csum,				0, 1, 0, 0, 0, 1,	6,	\
		TSO_F | L3L4CSUM_F)					\
T(tso_ol3ol4csum,			0, 1, 0, 0, 1, 0,	6,	\
		TSO_F | OL3OL4CSUM_F)					\
T(tso_ol3ol4csum_l3l4csum,		0, 1, 0, 0, 1, 1,	6,	\
		TSO_F | OL3OL4CSUM_F | L3L4CSUM_F)			\
T(tso_vlan,				0, 1, 0, 1, 0, 0,	6,	\
		TSO_F | VLAN_F)						\
T(tso_vlan_l3l4csum,			0, 1, 0, 1, 0, 1,	6,	\
		TSO_F | VLAN_F | L3L4CSUM_F)				\
T(tso_vlan_ol3ol4csum,			0, 1, 0, 1, 1, 0,	6,	\
		TSO_F | VLAN_F | OL3OL4CSUM_F)				\
T(tso_vlan_ol3ol4csum_l3l4csum,		0, 1, 0, 1, 1, 1,	6,	\
		TSO_F | VLAN_F | OL3OL4CSUM_F |	L3L4CSUM_F)		\
T(tso_noff,				0, 1, 1, 0, 0, 0,	6,	\
		TSO_F | NOFF_F)						\
T(tso_noff_l3l4csum,			0, 1, 1, 0, 0, 1,	6,	\
		TSO_F | NOFF_F | L3L4CSUM_F)				\
T(tso_noff_ol3ol4csum,			0, 1, 1, 0, 1, 0,	6,	\
		TSO_F | NOFF_F | OL3OL4CSUM_F)				\
T(tso_noff_ol3ol4csum_l3l4csum,		0, 1, 1, 0, 1, 1,	6,	\
		TSO_F | NOFF_F | OL3OL4CSUM_F |	L3L4CSUM_F)		\
T(tso_noff_vlan,			0, 1, 1, 1, 0, 0,	6,	\
		TSO_F | NOFF_F | VLAN_F)				\
T(tso_noff_vlan_l3l4csum,		0, 1, 1, 1, 0, 1,	6,	\
		TSO_F | NOFF_F | VLAN_F | L3L4CSUM_F)			\
T(tso_noff_vlan_ol3ol4csum,		0, 1, 1, 1, 1, 0,	6,	\
		TSO_F | NOFF_F | VLAN_F | OL3OL4CSUM_F)			\
T(tso_noff_vlan_ol3ol4csum_l3l4csum,	0, 1, 1, 1, 1, 1,	6,	\
		TSO_F | NOFF_F | VLAN_F | OL3OL4CSUM_F | L3L4CSUM_F)	\
T(ts,					1, 0, 0, 0, 0, 0,	8,	\
		TSP_F)							\
T(ts_l3l4csum,				1, 0, 0, 0, 0, 1,	8,	\
		TSP_F | L3L4CSUM_F)					\
T(ts_ol3ol4csum,			1, 0, 0, 0, 1, 0,	8,	\
		TSP_F | OL3OL4CSUM_F)					\
T(ts_ol3ol4csum_l3l4csum,		1, 0, 0, 0, 1, 1,	8,	\
		TSP_F | OL3OL4CSUM_F | L3L4CSUM_F)			\
T(ts_vlan,				1, 0, 0, 1, 0, 0,	8,	\
		TSP_F | VLAN_F)						\
T(ts_vlan_l3l4csum,			1, 0, 0, 1, 0, 1,	8,	\
		TSP_F | VLAN_F | L3L4CSUM_F)				\
T(ts_vlan_ol3ol4csum,			1, 0, 0, 1, 1, 0,	8,	\
		TSP_F | VLAN_F | OL3OL4CSUM_F)				\
T(ts_vlan_ol3ol4csum_l3l4csum,		1, 0, 0, 1, 1, 1,	8,	\
		TSP_F | VLAN_F | OL3OL4CSUM_F |	L3L4CSUM_F)		\
T(ts_noff,				1, 0, 1, 0, 0, 0,	8,	\
		TSP_F | NOFF_F)						\
T(ts_noff_l3l4csum,			1, 0, 1, 0, 0, 1,	8,	\
		TSP_F | NOFF_F | L3L4CSUM_F)				\
T(ts_noff_ol3ol4csum,			1, 0, 1, 0, 1, 0,	8,	\
		TSP_F | NOFF_F | OL3OL4CSUM_F)				\
T(ts_noff_ol3ol4csum_l3l4csum,		1, 0, 1, 0, 1, 1,	8,	\
		TSP_F | NOFF_F | OL3OL4CSUM_F |	L3L4CSUM_F)		\
T(ts_noff_vlan,				1, 0, 1, 1, 0, 0,	8,	\
		TSP_F | NOFF_F | VLAN_F)				\
T(ts_noff_vlan_l3l4csum,		1, 0, 1, 1, 0, 1,	8,	\
		TSP_F | NOFF_F | VLAN_F | L3L4CSUM_F)			\
T(ts_noff_vlan_ol3ol4csum,		1, 0, 1, 1, 1, 0,	8,	\
		TSP_F | NOFF_F | VLAN_F | OL3OL4CSUM_F)			\
T(ts_noff_vlan_ol3ol4csum_l3l4csum,	1, 0, 1, 1, 1, 1,	8,	\
		TSP_F | NOFF_F | VLAN_F | OL3OL4CSUM_F | L3L4CSUM_F)	\
T(ts_tso,				1, 1, 0, 0, 0, 0,	8,	\
		TSP_F | TSO_F)						\
T(ts_tso_l3l4csum,			1, 1, 0, 0, 0, 1,	8,	\
		TSP_F | TSO_F | L3L4CSUM_F)				\
T(ts_tso_ol3ol4csum,			1, 1, 0, 0, 1, 0,	8,	\
		TSP_F | TSO_F | OL3OL4CSUM_F)				\
T(ts_tso_ol3ol4csum_l3l4csum,		1, 1, 0, 0, 1, 1,	8,	\
		TSP_F | TSO_F | OL3OL4CSUM_F | L3L4CSUM_F)		\
T(ts_tso_vlan,				1, 1, 0, 1, 0, 0,	8,	\
		TSP_F | TSO_F | VLAN_F)					\
T(ts_tso_vlan_l3l4csum,			1, 1, 0, 1, 0, 1,	8,	\
		TSP_F | TSO_F | VLAN_F | L3L4CSUM_F)			\
T(ts_tso_vlan_ol3ol4csum,		1, 1, 0, 1, 1, 0,	8,	\
		TSP_F | TSO_F | VLAN_F | OL3OL4CSUM_F)			\
T(ts_tso_vlan_ol3ol4csum_l3l4csum,	1, 1, 0, 1, 1, 1,	8,	\
		TSP_F | TSO_F | VLAN_F | OL3OL4CSUM_F |	L3L4CSUM_F)	\
T(ts_tso_noff,				1, 1, 1, 0, 0, 0,	8,	\
		TSP_F | TSO_F | NOFF_F)					\
T(ts_tso_noff_l3l4csum,			1, 1, 1, 0, 0, 1,	8,	\
		TSP_F | TSO_F | NOFF_F | L3L4CSUM_F)			\
T(ts_tso_noff_ol3ol4csum,		1, 1, 1, 0, 1, 0,	8,	\
		TSP_F | TSO_F | NOFF_F | OL3OL4CSUM_F)			\
T(ts_tso_noff_ol3ol4csum_l3l4csum,	1, 1, 1, 0, 1, 1,	8,	\
		TSP_F | TSO_F | NOFF_F | OL3OL4CSUM_F |	L3L4CSUM_F)	\
T(ts_tso_noff_vlan,			1, 1, 1, 1, 0, 0,	8,	\
		TSP_F | TSO_F | NOFF_F | VLAN_F)			\
T(ts_tso_noff_vlan_l3l4csum,		1, 1, 1, 1, 0, 1,	8,	\
		TSP_F | TSO_F | NOFF_F | VLAN_F | L3L4CSUM_F)		\
T(ts_tso_noff_vlan_ol3ol4csum,		1, 1, 1, 1, 1, 0,	8,	\
		TSP_F | TSO_F | NOFF_F | VLAN_F | OL3OL4CSUM_F)		\
T(ts_tso_noff_vlan_ol3ol4csum_l3l4csum,	1, 1, 1, 1, 1, 1,	8,	\
		TSP_F | TSO_F | NOFF_F | VLAN_F | OL3OL4CSUM_F | L3L4CSUM_F)

#define T(name, f5, f4, f3, f2, f1, f0, sz, flags)			       \
	uint16_t __rte_noinline __rte_hot cn10k_nix_xmit_pkts_##name(          \
		void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t pkts);     \
									       \
	uint16_t __rte_noinline __rte_hot cn10k_nix_xmit_pkts_mseg_##name(     \
		void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t pkts);     \
									       \
	uint16_t __rte_noinline __rte_hot cn10k_nix_xmit_pkts_vec_##name(      \
		void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t pkts);

NIX_TX_FASTPATH_MODES
#undef T

#endif /* __CN10K_TX_H__ */