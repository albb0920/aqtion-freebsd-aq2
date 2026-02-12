/* $OpenBSD: if_aq_pci.c,v 1.34 2026/01/15 06:41:21 dlg Exp $ */
/*	$NetBSD: if_aq.c,v 1.27 2021/06/16 00:21:18 riastradh Exp $	*/

/*
 * Copyright (c) 2021 Jonathan Matthew <jonathan@d14n.org>
 * Copyright (c) 2021 Mike Larkin <mlarkin@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * aQuantia Corporation Network Driver
 * Copyright (C) 2014-2017 aQuantia Corporation. All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   (1) Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer.
 *
 *   (2) Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   (3) The name of the author may not be used to endorse or promote
 *   products derived from this software without specific prior
 *   written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @file aq_fw_a2.c
 * Atlantic2 firmware interface helpers.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/bitstring.h>
#include <sys/endian.h>
#include <sys/mbuf.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/types.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/iflib.h>

#include "aq_common.h"
#include "aq_device.h"
#include "aq_fw.h"
#include "aq_hw.h"
#include "aq_hw_llh.h"

extern const struct aq_firmware_ops aq_fw_a2_ops;

#define AQ2_MIF_HOST_FINISHED_STATUS_WRITE_REG	0x0e00u
#define AQ2_MIF_HOST_FINISHED_STATUS_READ_REG	0x0e04u
#define AQ2_MIF_HOST_FINISHED_STATUS_ACK	(1u << 0)

#define AQ2_MCP_HOST_REQ_INT_REG		0x0f00u
#define AQ2_MCP_HOST_REQ_INT_READY		(1u << 0)
#define AQ2_MCP_HOST_REQ_INT_CLR_REG		0x0f08u

#define AQ2_MIF_BOOT_REG			0x3040u
#define AQ2_MIF_BOOT_BOOT_STARTED		(1u << 24)
#define AQ2_MIF_BOOT_FW_INIT_FAILED		(1u << 29)
#define AQ2_MIF_BOOT_FW_INIT_COMP_SUCCESS	(1u << 31)

#define AQ2_FW_INTERFACE_IN_MTU_REG		0x12000u
#define AQ2_FW_INTERFACE_IN_MAC_ADDRESS_REG	0x12008u

#define AQ2_FW_INTERFACE_IN_LINK_CONTROL_REG	0x12010u
#define AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE	0x0000000fu
#define AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_ACTIVE		1u
#define AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_SLEEP_PROXY	2u
#define AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_SHUTDOWN		4u

#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_REG		0x12018u
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_PAUSE_TX	(1u << 25)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_PAUSE_RX	(1u << 24)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_10G	(1u << 20)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_5G	(1u << 19)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_2G5	(1u << 18)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_1G	(1u << 17)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_100M	(1u << 16)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10G	(1u << 15)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_N5G	(1u << 14)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_5G	(1u << 13)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_N2G5	(1u << 12)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_2G5	(1u << 11)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_1G	(1u << 10)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_100M	(1u << 9)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10M	(1u << 8)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_1G_HD	(1u << 7)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_100M_HD	(1u << 6)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10M_HD	(1u << 5)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_LINK_UP	(1u << 0)

#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_REG				0x12a58u
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_MCAST_QUEUE_OR_TC		0x00800000u
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_MCAST_RX_QUEUE_TC_INDEX	0x007c0000u
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_MCAST_ACCEPT		0x00010000u
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_BCAST_QUEUE_OR_TC		0x00008000u
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_BCAST_RX_QUEUE_TC_INDEX	0x00007c00u
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_BCAST_ACCEPT		0x00000100u
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_PROMISC_QUEUE_OR_TC		0x00000080u
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_PROMISC_RX_QUEUE_TX_INDEX	0x0000007cu

#define AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_REG	0x13000u
#define AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_B	0xffff0000u
#define AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_B_S 16
#define AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_A	0x0000ffffu
#define AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_A_S	0

#define AQ2_FW_INTERFACE_OUT_VERSION_BUNDLE_REG	0x13004u
#define AQ2_FW_INTERFACE_OUT_VERSION_IFACE_REG	0x13010u

#define AQ2_FW_INTERFACE_OUT_VERSION_BUILD	0xffff0000u
#define AQ2_FW_INTERFACE_OUT_VERSION_BUILD_S	16
#define AQ2_FW_INTERFACE_OUT_VERSION_MINOR	0x0000ff00u
#define AQ2_FW_INTERFACE_OUT_VERSION_MINOR_S	8
#define AQ2_FW_INTERFACE_OUT_VERSION_MAJOR	0x000000ffu
#define AQ2_FW_INTERFACE_OUT_VERSION_MAJOR_S	0

#define AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER	0x0000000fu

#define AQ2_FW_INTERFACE_OUT_LINK_STATUS_REG	0x13014u
#define AQ2_FW_INTERFACE_OUT_LINK_STATUS_PAUSE_RX	(1u << 9)
#define AQ2_FW_INTERFACE_OUT_LINK_STATUS_PAUSE_TX	(1u << 8)
#define AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE		0x000000f0u
#define AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_S	4
#define AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_10G	6
#define AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_5G	5
#define AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_2G5	4
#define AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_1G	3
#define AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_100M	2
#define AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_10M	1

#define AQ2_FW_INTERFACE_OUT_FILTER_CAPS_REG	0x13774u
#define AQ2_FW_INTERFACE_OUT_FILTER_CAPS3_RESOLVER_BASE_INDEX 0x00ff0000u
#define AQ2_FW_INTERFACE_OUT_FILTER_CAPS3_RESOLVER_BASE_INDEX_SHIFT 16

#define AQ2_FW_INTERFACE_OUT_STATS_REG		0x13700u
#define AQ2_FW_INTERFACE_IN_SLEEP_PROXY_REG	0x12028u

struct aq2_wake_on_lan {
	uint8_t wake_on_magic_packet:1;
	uint8_t wake_on_pattern:1;
	uint8_t wake_on_link_up:1;
	uint8_t wake_on_link_down:1;
	uint8_t wake_on_ping:1;
	uint8_t wake_on_timer:1;
	uint8_t rsvd:2;

	uint8_t rsvd2;
	uint16_t rsvd3;

	uint32_t link_up_timeout;
	uint32_t link_down_timeout;
	uint32_t timer;
} __attribute__((__packed__));

struct aq2_stats_msm {
	uint64_t tx_unicast_octets;
	uint64_t tx_multicast_octets;
	uint64_t tx_broadcast_octets;
	uint64_t rx_unicast_octets;
	uint64_t rx_multicast_octets;
	uint64_t rx_broadcast_octets;

	uint32_t tx_unicast_frames;
	uint32_t tx_multicast_frames;
	uint32_t tx_broadcast_frames;
	uint32_t tx_errors;

	uint32_t rx_unicast_frames;
	uint32_t rx_multicast_frames;
	uint32_t rx_broadcast_frames;
	uint32_t rx_dropped_frames;
	uint32_t rx_error_frames;

	uint32_t tx_good_frames;
	uint32_t rx_good_frames;
	uint32_t reserve_fw_gap;
} __attribute__((__packed__));

struct aq2_stats_a0 {
	struct {
		uint32_t link_up;
		uint32_t link_down;
	} link;
	struct aq2_stats_msm msm;
	uint32_t main_loop_cycles;
	uint32_t reserve_fw_gap;
} __attribute__((__packed__));

struct aq2_stats_b0 {
	uint64_t rx_good_octets;
	uint64_t rx_pause_frames;
	uint64_t rx_good_frames;
	uint64_t rx_errors;
	uint64_t rx_unicast_frames;
	uint64_t rx_multicast_frames;
	uint64_t rx_broadcast_frames;

	uint64_t tx_good_octets;
	uint64_t tx_pause_frames;
	uint64_t tx_good_frames;
	uint64_t tx_errors;
	uint64_t tx_unicast_frames;
	uint64_t tx_multicast_frames;
	uint64_t tx_broadcast_frames;

	uint32_t main_loop_cycles;
} __attribute__((__packed__));

struct aq2_transaction_counter {
	uint16_t transaction_cnt_a;
	uint16_t transaction_cnt_b;
} __attribute__((__packed__));

struct aq2_version {
	struct {
		uint8_t major;
		uint8_t minor;
		uint16_t build;
	} bundle;
	struct {
		uint8_t major;
		uint8_t minor;
		uint16_t build;
	} mac;
	struct {
		uint8_t major;
		uint8_t minor;
		uint16_t build;
	} phy;
	uint32_t drv_iface_ver:4;
	uint32_t rsvd:28;
} __attribute__((__packed__));

struct aq2_link_status {
	uint8_t link_state:4;
	uint8_t link_rate:4;

	uint8_t pause_tx:1;
	uint8_t pause_rx:1;
	uint8_t eee:1;
	uint8_t duplex:1;
	uint8_t rsvd:4;

	uint16_t rsvd2;
} __attribute__((__packed__));

struct aq2_sleep_proxy_caps {
	uint8_t ipv4_offload:1;
	uint8_t ipv6_offload:1;
	uint8_t tcp_port_offload:1;
	uint8_t udp_port_offload:1;
	uint8_t ka4_offload:1;
	uint8_t ka6_offload:1;
	uint8_t mdns_offload:1;
	uint8_t wake_on_ping:1;

	uint8_t wake_on_magic_packet:1;
	uint8_t wake_on_pattern:1;
	uint8_t wake_on_timer:1;
	uint8_t wake_on_link:1;
	uint8_t wake_patterns_count:4;

	uint8_t ipv4_count;
	uint8_t ipv6_count;

	uint8_t tcp_port_offload_count;
	uint8_t udp_port_offload_count;

	uint8_t tcp4_ka_count;
	uint8_t tcp6_ka_count;

	uint8_t igmp_offload:1;
	uint8_t mld_offload:1;
	uint8_t rsvd:6;

	uint8_t rsvd2;
	uint16_t rsvd3;
} __attribute__((__packed__));

struct aq2_device_link_caps {
	uint8_t rsvd:3;
	uint8_t internal_loopback:1;
	uint8_t external_loopback:1;
	uint8_t rate_10M_hd:1;
	uint8_t rate_100M_hd:1;
	uint8_t rate_1G_hd:1;

	uint8_t rate_10M:1;
	uint8_t rate_100M:1;
	uint8_t rate_1G:1;
	uint8_t rate_2P5G:1;
	uint8_t rate_N2P5G:1;
	uint8_t rate_5G:1;
	uint8_t rate_N5G:1;
	uint8_t rate_10G:1;

	uint8_t rsvd3:1;
	uint8_t eee_100M:1;
	uint8_t eee_1G:1;
	uint8_t eee_2P5G:1;
	uint8_t rsvd4:1;
	uint8_t eee_5G:1;
	uint8_t rsvd5:1;
	uint8_t eee_10G:1;

	uint8_t pause_rx:1;
	uint8_t pause_tx:1;
	uint8_t pfc:1;
	uint8_t downshift:1;
	uint8_t downshift_retry:4;
} __attribute__((__packed__));

struct aq2_lkp_link_caps {
	uint8_t rsvd:5;
	uint8_t rate_10M_hd:1;
	uint8_t rate_100M_hd:1;
	uint8_t rate_1G_hd:1;

	uint8_t rate_10M:1;
	uint8_t rate_100M:1;
	uint8_t rate_1G:1;
	uint8_t rate_2P5G:1;
	uint8_t rate_N2P5G:1;
	uint8_t rate_5G:1;
	uint8_t rate_N5G:1;
	uint8_t rate_10G:1;

	uint8_t rsvd2:1;
	uint8_t eee_100M:1;
	uint8_t eee_1G:1;
	uint8_t eee_2P5G:1;
	uint8_t rsvd3:1;
	uint8_t eee_5G:1;
	uint8_t rsvd4:1;
	uint8_t eee_10G:1;

	uint8_t pause_rx:1;
	uint8_t pause_tx:1;
	uint8_t rsvd5:6;
} __attribute__((__packed__));

struct aq2_cable_diag_lane_data {
	uint8_t result_code;
	uint8_t dist;
	uint8_t far_dist;
	uint8_t rsvd;
} __attribute__((__packed__));

struct aq2_cable_diag_status {
	struct aq2_cable_diag_lane_data lane_data[4];
	uint8_t transact_id;
	uint8_t status:4;
	uint8_t rsvd:4;
	uint16_t rsvd2;
} __attribute__((__packed__));

struct aq2_wol_status {
	uint8_t wake_count;
	uint8_t wake_reason;

	uint16_t wake_up_packet_length:12;
	uint16_t wake_up_pattern_number:3;
	uint16_t rsvd:1;

	uint32_t wake_up_packet[379];
} __attribute__((__packed__));

struct aq2_mac_health_monitor {
	uint8_t mac_ready:1;
	uint8_t mac_fault:1;
	uint8_t mac_flashless_finished:1;
	uint8_t rsvd:5;

	uint8_t mac_temperature;
	uint16_t mac_heart_beat;
	uint16_t mac_fault_code;
	uint16_t rsvd2;
} __attribute__((__packed__));

struct aq2_phy_health_monitor {
	uint8_t phy_ready:1;
	uint8_t phy_fault:1;
	uint8_t phy_hot_warning:1;
	uint8_t rsvd:5;

	uint8_t phy_temperature;
	uint16_t phy_heart_beat;
	uint16_t phy_fault_code;
	uint16_t rsvd2;
} __attribute__((__packed__));

struct aq2_fw_interface_out_prefix {
	struct aq2_transaction_counter transaction_id;
	struct aq2_version version;
	struct aq2_link_status link_status;
	struct aq2_wol_status wol_status;
	uint32_t rsvd;
	uint32_t rsvd2;
	struct aq2_mac_health_monitor mac_health_monitor;
	uint32_t rsvd3;
	uint32_t rsvd4;
	struct aq2_phy_health_monitor phy_health_monitor;
} __attribute__((__packed__));

struct aq2_fw_interface_out_caps {
	struct aq2_transaction_counter transaction_id;
	struct aq2_version version;
	struct aq2_link_status link_status;
	struct aq2_wol_status wol_status;
	uint32_t rsvd;
	uint32_t rsvd2;
	struct aq2_mac_health_monitor mac_health_monitor;
	uint32_t rsvd3;
	uint32_t rsvd4;
	struct aq2_phy_health_monitor phy_health_monitor;
	uint32_t rsvd5;
	uint32_t rsvd6;
	struct aq2_cable_diag_status cable_diag_status;
	uint32_t rsvd7;
	struct aq2_device_link_caps device_link_caps;
	uint32_t rsvd8;
	struct aq2_sleep_proxy_caps sleep_proxy_caps;
	uint32_t rsvd9;
	struct aq2_lkp_link_caps lkp_link_caps;
} __attribute__((__packed__));

union aq2_stats_buf {
	struct aq2_stats_a0 a0;
	struct aq2_stats_b0 b0;
	uint32_t raw[29];
};

static uint32_t aq2_u64_to_u32(uint64_t val)
{
	return (uint32_t)(val & 0xffffffffu);
}

static void aq2_stats_from_a0(struct aq_hw *hw, struct aq_hw_stats_s *stats,
    const struct aq2_stats_a0 *a0)
{
	uint64_t rx_uc_oct = le64toh(a0->msm.rx_unicast_octets);
	uint64_t rx_mc_oct = le64toh(a0->msm.rx_multicast_octets);
	uint64_t rx_bc_oct = le64toh(a0->msm.rx_broadcast_octets);
	uint64_t tx_uc_oct = le64toh(a0->msm.tx_unicast_octets);
	uint64_t tx_mc_oct = le64toh(a0->msm.tx_multicast_octets);
	uint64_t tx_bc_oct = le64toh(a0->msm.tx_broadcast_octets);

	uint32_t rx_uc_frames = le32toh(a0->msm.rx_unicast_frames);
	uint32_t rx_mc_frames = le32toh(a0->msm.rx_multicast_frames);
	uint32_t rx_bc_frames = le32toh(a0->msm.rx_broadcast_frames);
	uint32_t rx_errs = le32toh(a0->msm.rx_error_frames);
	uint32_t rx_drops = le32toh(a0->msm.rx_dropped_frames);

	uint32_t tx_uc_frames = le32toh(a0->msm.tx_unicast_frames);
	uint32_t tx_mc_frames = le32toh(a0->msm.tx_multicast_frames);
	uint32_t tx_bc_frames = le32toh(a0->msm.tx_broadcast_frames);
	uint32_t tx_errs = le32toh(a0->msm.tx_errors);

	stats->uprc = rx_uc_frames;
	stats->mprc = rx_mc_frames;
	stats->bprc = rx_bc_frames;
	stats->erpr = rx_errs;

	stats->uptc = tx_uc_frames;
	stats->mptc = tx_mc_frames;
	stats->bptc = tx_bc_frames;
	stats->erpt = tx_errs;

	stats->ubrc = aq2_u64_to_u32(rx_uc_oct);
	stats->mbrc = aq2_u64_to_u32(rx_mc_oct);
	stats->bbrc = aq2_u64_to_u32(rx_bc_oct);

	stats->ubtc = aq2_u64_to_u32(tx_uc_oct);
	stats->mbtc = aq2_u64_to_u32(tx_mc_oct);
	stats->bbtc = aq2_u64_to_u32(tx_bc_oct);

	stats->ptc = tx_uc_frames + tx_mc_frames + tx_bc_frames;
	stats->prc = rx_uc_frames + rx_mc_frames + rx_bc_frames;
	stats->dpc = rx_drops ? rx_drops : reg_rx_dma_stat_counter7get(hw);
}

static void aq2_stats_from_b0(struct aq_hw *hw, struct aq_hw_stats_s *stats,
    const struct aq2_stats_b0 *b0)
{
	uint64_t rx_good_oct = le64toh(b0->rx_good_octets);
	uint64_t tx_good_oct = le64toh(b0->tx_good_octets);

	uint32_t rx_uc_frames = aq2_u64_to_u32(le64toh(b0->rx_unicast_frames));
	uint32_t rx_mc_frames = aq2_u64_to_u32(le64toh(b0->rx_multicast_frames));
	uint32_t rx_bc_frames = aq2_u64_to_u32(le64toh(b0->rx_broadcast_frames));
	uint32_t rx_errs = aq2_u64_to_u32(le64toh(b0->rx_errors));

	uint32_t tx_uc_frames = aq2_u64_to_u32(le64toh(b0->tx_unicast_frames));
	uint32_t tx_mc_frames = aq2_u64_to_u32(le64toh(b0->tx_multicast_frames));
	uint32_t tx_bc_frames = aq2_u64_to_u32(le64toh(b0->tx_broadcast_frames));
	uint32_t tx_errs = aq2_u64_to_u32(le64toh(b0->tx_errors));

	stats->uprc = rx_uc_frames;
	stats->mprc = rx_mc_frames;
	stats->bprc = rx_bc_frames;
	stats->erpr = rx_errs;

	stats->uptc = tx_uc_frames;
	stats->mptc = tx_mc_frames;
	stats->bptc = tx_bc_frames;
	stats->erpt = tx_errs;

	stats->ubrc = aq2_u64_to_u32(rx_good_oct);
	stats->mbrc = 0;
	stats->bbrc = 0;

	stats->ubtc = aq2_u64_to_u32(tx_good_oct);
	stats->mbtc = 0;
	stats->bbtc = 0;

	stats->ptc = tx_uc_frames + tx_mc_frames + tx_bc_frames;
	stats->prc = rx_uc_frames + rx_mc_frames + rx_bc_frames;
	stats->dpc = reg_rx_dma_stat_counter7get(hw);
}

static int aq2_interface_buffer_read(struct aq_hw *hw, uint32_t reg0, uint32_t *data0,
    uint32_t size0)
{
	uint32_t tid0;
	uint32_t tid1;
	uint32_t reg;
	uint32_t *data;
	uint32_t size;
	int timo;

	for (timo = 10000; timo > 0; --timo) {
		tid0 = AQ_READ_REG(hw, AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_REG);
		if (((tid0 & AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_A) >>
		    AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_A_S) !=
		    ((tid0 & AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_B) >>
		    AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_B_S)) {
			usec_delay(10);
			continue;
		}

		for (reg = reg0, data = data0, size = size0;
		    size >= 4; reg += 4, ++data, size -= 4) {
			*data = AQ_READ_REG(hw, reg);
		}

		tid1 = AQ_READ_REG(hw, AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_REG);
		if (tid0 == tid1)
			break;
	}

	if (timo == 0)
		return -ETIMEDOUT;
	return 0;
}

static int aq2_fw_wait_shared_ack(struct aq_hw *hw)
{
	int timo;
	uint32_t v;

	AQ_WRITE_REG(hw, AQ2_MIF_HOST_FINISHED_STATUS_WRITE_REG,
	    AQ2_MIF_HOST_FINISHED_STATUS_ACK);

	for (timo = 100000; timo > 0; --timo) {
		v = AQ_READ_REG(hw, AQ2_MIF_HOST_FINISHED_STATUS_READ_REG);
		if ((v & AQ2_MIF_HOST_FINISHED_STATUS_ACK) == 0)
			return 0;
		usec_delay(100);
	}

	return -ETIMEDOUT;
}

int aq2_fw_reboot(struct aq_hw *hw)
{
	uint32_t v;
	uint32_t filter_caps[3];
	int timo;
	int err;

	hw->fw_ops = &aq_fw_a2_ops;
	hw->chip_features |= AQ_HW_CHIP_ANTIGUA;

	AQ_WRITE_REG(hw, AQ2_MCP_HOST_REQ_INT_CLR_REG, 1);
	AQ_WRITE_REG(hw, AQ2_MIF_BOOT_REG, 1);

	for (timo = 200000; timo > 0; --timo) {
		v = AQ_READ_REG(hw, AQ2_MIF_BOOT_REG);
		if ((v & AQ2_MIF_BOOT_BOOT_STARTED) && v != 0xffffffffu)
			break;
		usec_delay(10);
	}
	if (timo == 0)
		return -ETIMEDOUT;

	for (timo = 2000000; timo > 0; --timo) {
		v = AQ_READ_REG(hw, AQ2_MIF_BOOT_REG);
		if ((v & AQ2_MIF_BOOT_FW_INIT_FAILED) ||
		    (v & AQ2_MIF_BOOT_FW_INIT_COMP_SUCCESS))
			break;
		v = AQ_READ_REG(hw, AQ2_MCP_HOST_REQ_INT_REG);
		if (v & AQ2_MCP_HOST_REQ_INT_READY)
			break;
		usec_delay(10);
	}
	if (timo == 0)
		return -ETIMEDOUT;

	v = AQ_READ_REG(hw, AQ2_MIF_BOOT_REG);
	if (v & AQ2_MIF_BOOT_FW_INIT_FAILED)
		return -ETIMEDOUT;

	v = AQ_READ_REG(hw, AQ2_MCP_HOST_REQ_INT_REG);
	if (v & AQ2_MCP_HOST_REQ_INT_READY)
		return -ENXIO;

	err = aq2_interface_buffer_read(hw,
	    AQ2_FW_INTERFACE_OUT_VERSION_BUNDLE_REG, &v, sizeof(v));
	if (err != 0)
		return err;

	hw->fw_version.raw =
	    (((v & AQ2_FW_INTERFACE_OUT_VERSION_MAJOR) >>
		AQ2_FW_INTERFACE_OUT_VERSION_MAJOR_S) << 24) |
	    (((v & AQ2_FW_INTERFACE_OUT_VERSION_MINOR) >>
		AQ2_FW_INTERFACE_OUT_VERSION_MINOR_S) << 16) |
	    (((v & AQ2_FW_INTERFACE_OUT_VERSION_BUILD) >>
		AQ2_FW_INTERFACE_OUT_VERSION_BUILD_S));

	hw->aq2_iface_ver = AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER_A0;
	err = aq2_interface_buffer_read(hw,
	    AQ2_FW_INTERFACE_OUT_VERSION_IFACE_REG, &v, sizeof(v));
	if (err != 0)
		return err;

	switch (v & AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER) {
	case AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER_A0:
	case AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER_B0:
		hw->aq2_iface_ver = (uint8_t)(v & AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER);
		break;
	default:
		hw->aq2_iface_ver = AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER_A0;
		break;
	}

	err = aq2_interface_buffer_read(hw,
	    AQ2_FW_INTERFACE_OUT_FILTER_CAPS_REG, filter_caps,
	    sizeof(filter_caps));
	if (err != 0)
		return err;

	hw->art_base_index = ((filter_caps[2] &
	    AQ2_FW_INTERFACE_OUT_FILTER_CAPS3_RESOLVER_BASE_INDEX) >>
	    AQ2_FW_INTERFACE_OUT_FILTER_CAPS3_RESOLVER_BASE_INDEX_SHIFT) * 8;

	return 0;
}

static int aq2_fw_reset(struct aq_hw *hw)
{
	uint32_t v;
	int err;

	AQ_WRITE_REG_BIT(hw, AQ2_FW_INTERFACE_IN_LINK_CONTROL_REG,
	    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE, 0,
	    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_ACTIVE);

	AQ_WRITE_REG(hw, AQ2_FW_INTERFACE_IN_MTU_REG,
	    aq_hw_mtu_jumbo(hw));

	v = AQ_READ_REG(hw, AQ2_FW_INTERFACE_IN_REQUEST_POLICY_REG);
	v |= AQ2_FW_INTERFACE_IN_REQUEST_POLICY_MCAST_QUEUE_OR_TC;
	v &= ~AQ2_FW_INTERFACE_IN_REQUEST_POLICY_MCAST_RX_QUEUE_TC_INDEX;
	v |= AQ2_FW_INTERFACE_IN_REQUEST_POLICY_MCAST_ACCEPT;
	v |= AQ2_FW_INTERFACE_IN_REQUEST_POLICY_BCAST_QUEUE_OR_TC;
	v &= ~AQ2_FW_INTERFACE_IN_REQUEST_POLICY_BCAST_RX_QUEUE_TC_INDEX;
	v |= AQ2_FW_INTERFACE_IN_REQUEST_POLICY_BCAST_ACCEPT;
	v |= AQ2_FW_INTERFACE_IN_REQUEST_POLICY_PROMISC_QUEUE_OR_TC;
	v &= ~AQ2_FW_INTERFACE_IN_REQUEST_POLICY_PROMISC_RX_QUEUE_TX_INDEX;
	AQ_WRITE_REG(hw, AQ2_FW_INTERFACE_IN_REQUEST_POLICY_REG, v);

	err = aq2_fw_wait_shared_ack(hw);
	return err;
}

static int aq2_fw_get_mac_addr(struct aq_hw *hw, uint8_t *mac)
{
	uint32_t mac_addr[2];
	int err;

	err = aq2_interface_buffer_read(hw, AQ2_FW_INTERFACE_IN_MAC_ADDRESS_REG,
	    mac_addr, sizeof(mac_addr));
	if (err != 0)
		return err;

	if (mac_addr[0] == 0 && mac_addr[1] == 0)
		return -ENXIO;

	mac_addr[0] = htole32(mac_addr[0]);
	mac_addr[1] = htole32(mac_addr[1]);
	memcpy(mac, (uint8_t *)mac_addr, ETHER_ADDR_LEN);

	return 0;
}

static int aq2_fw_set_mode(struct aq_hw *hw, enum aq_hw_fw_mpi_state_e mode,
    aq_fw_link_speed_t speed)
{
	uint32_t v;

	v = AQ_READ_REG(hw, AQ2_FW_INTERFACE_IN_LINK_OPTIONS_REG);
	v &= ~(AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10G |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_N5G |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_5G |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_N2G5 |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_2G5 |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_1G |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_100M |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10M |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_1G_HD |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_100M_HD |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10M_HD);

	v &= ~AQ2_FW_INTERFACE_IN_LINK_OPTIONS_LINK_UP;

	if (speed & aq_fw_10G)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10G;
	if (speed & aq_fw_5G)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_N5G |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_5G;
	if (speed & aq_fw_2G5)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_N2G5 |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_2G5;
	if (speed & aq_fw_1G)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_1G |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_1G_HD;
	if (speed & aq_fw_100M)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_100M |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_100M_HD;
	if (speed & aq_fw_10M)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10M |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10M_HD;

	v &= ~(AQ2_FW_INTERFACE_IN_LINK_OPTIONS_PAUSE_TX |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_PAUSE_RX);
	if (hw->fc.fc_tx)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_PAUSE_TX;
	if (hw->fc.fc_rx)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_PAUSE_RX;

	if (mode == MPI_INIT) {
		v &= ~(AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_10G |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_5G |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_2G5 |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_1G |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_100M);
		if (hw->eee_rate & AQ_EEE_10G)
			v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_10G;
		if (hw->eee_rate & AQ_EEE_5G)
			v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_5G;
		if (hw->eee_rate & AQ_EEE_2G5)
			v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_2G5;
		if (hw->eee_rate & AQ_EEE_1G)
			v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_1G;
		if (hw->eee_rate & AQ_EEE_100M)
			v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_100M;
	}

	if (mode == MPI_DEINIT || speed == aq_fw_none) {
		AQ_WRITE_REG_BIT(hw, AQ2_FW_INTERFACE_IN_LINK_CONTROL_REG,
		    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE, 0,
		    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_SHUTDOWN);
	} else {
		AQ_WRITE_REG_BIT(hw, AQ2_FW_INTERFACE_IN_LINK_CONTROL_REG,
		    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE, 0,
		    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_ACTIVE);
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_LINK_UP;
	}

	AQ_WRITE_REG(hw, AQ2_FW_INTERFACE_IN_LINK_OPTIONS_REG, v);
	return aq2_fw_wait_shared_ack(hw);
}

static int aq2_fw_get_mode(struct aq_hw *hw, enum aq_hw_fw_mpi_state_e *mode,
    aq_fw_link_speed_t *speed, aq_fw_link_fc_t *fc)
{
	uint32_t v;
	aq_fw_link_speed_t speed_val = aq_fw_none;
	aq_fw_link_fc_t fc_val = aq_fw_fc_none;

	if (mode)
		*mode = MPI_INIT;

	v = AQ_READ_REG(hw, AQ2_FW_INTERFACE_OUT_LINK_STATUS_REG);
	switch ((v & AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE) >>
	    AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_S) {
	case AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_10G:
		speed_val = aq_fw_10G;
		break;
	case AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_5G:
		speed_val = aq_fw_5G;
		break;
	case AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_2G5:
		speed_val = aq_fw_2G5;
		break;
	case AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_1G:
		speed_val = aq_fw_1G;
		break;
	case AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_100M:
		speed_val = aq_fw_100M;
		break;
	case AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_10M:
		speed_val = aq_fw_10M;
		break;
	default:
		speed_val = aq_fw_none;
		break;
	}

	if (speed)
		*speed = speed_val;

	if (v & AQ2_FW_INTERFACE_OUT_LINK_STATUS_PAUSE_TX)
		fc_val |= aq_fw_fc_ENABLE_TX;
	if (v & AQ2_FW_INTERFACE_OUT_LINK_STATUS_PAUSE_RX)
		fc_val |= aq_fw_fc_ENABLE_RX;
	if (fc)
		*fc = fc_val;

	return 0;
}

static int aq2_fw_get_stats(struct aq_hw *hw, struct aq_hw_stats_s *stats)
{
	union aq2_stats_buf stats_buf;
	int err;

	err = aq2_interface_buffer_read(hw, AQ2_FW_INTERFACE_OUT_STATS_REG,
	    stats_buf.raw, sizeof(stats_buf));
	if (err == 0) {
		if (hw->aq2_iface_ver == AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER_B0)
			aq2_stats_from_b0(hw, stats, &stats_buf.b0);
		else
			aq2_stats_from_a0(hw, stats, &stats_buf.a0);
		return 0;
	}

	uint32_t rx_uc_frames = reg_mac_msm_rx_ucst_frm_cnt_get(hw);
	uint32_t rx_mc_frames = reg_mac_msm_rx_mcst_frm_cnt_get(hw);
	uint32_t rx_bc_frames = reg_mac_msm_rx_bcst_frm_cnt_get(hw);
	uint32_t rx_errs = reg_mac_msm_rx_errs_cnt_get(hw);
	uint32_t tx_uc_frames = reg_mac_msm_tx_ucst_frm_cnt_get(hw);
	uint32_t tx_mc_frames = reg_mac_msm_tx_mcst_frm_cnt_get(hw);
	uint32_t tx_bc_frames = reg_mac_msm_tx_bcst_frm_cnt_get(hw);
	uint32_t tx_errs = reg_mac_msm_tx_errs_cnt_get(hw);
	uint32_t rx_uc_oct = reg_mac_msm_rx_ucst_octets_counter0get(hw);
	uint32_t rx_bc_oct = reg_mac_msm_rx_bcst_octets_counter1get(hw);
	uint32_t rx_total_oct = stats_rx_dma_good_octet_counterlsw_get(hw);
	uint32_t tx_uc_oct = reg_mac_msm_tx_ucst_octets_counter0get(hw);
	uint32_t tx_mc_oct = reg_mac_msm_tx_mcst_octets_counter1get(hw);
	uint32_t tx_bc_oct = reg_mac_msm_tx_bcst_octets_counter1get(hw);
	uint32_t rx_mc_oct = 0;

	if (rx_total_oct >= (rx_uc_oct + rx_bc_oct))
		rx_mc_oct = rx_total_oct - rx_uc_oct - rx_bc_oct;

	stats->uprc = rx_uc_frames;
	stats->mprc = rx_mc_frames;
	stats->bprc = rx_bc_frames;
	stats->erpr = rx_errs;

	stats->uptc = tx_uc_frames;
	stats->mptc = tx_mc_frames;
	stats->bptc = tx_bc_frames;
	stats->erpt = tx_errs;

	stats->ubrc = rx_uc_oct;
	stats->mbrc = rx_mc_oct;
	stats->bbrc = rx_bc_oct;

	stats->ubtc = tx_uc_oct;
	stats->mbtc = tx_mc_oct;
	stats->bbtc = tx_bc_oct;

	stats->ptc = tx_uc_frames + tx_mc_frames + tx_bc_frames;
	stats->prc = rx_uc_frames + rx_mc_frames + rx_bc_frames;
	stats->dpc = reg_rx_dma_stat_counter7get(hw);

	return 0;
}

int aq2_fw_set_wol(struct aq_hw *hw, uint32_t wol_flags, const uint8_t *mac)
{
	struct aq2_wake_on_lan wol;
	uint32_t mac_addr[2];
	uint32_t *data;
	uint32_t reg;
	uint32_t size;

	memset(&wol, 0, sizeof(wol));
	if (wol_flags & AQ_WOL_MAGIC)
		wol.wake_on_magic_packet = 1u;
	if (wol_flags & AQ_WOL_PHY)
		wol.wake_on_link_up = 1u;

	memset(mac_addr, 0, sizeof(mac_addr));
	memcpy(mac_addr, mac, ETHER_ADDR_LEN);
	mac_addr[0] = htole32(mac_addr[0]);
	mac_addr[1] = htole32(mac_addr[1]);

	AQ_WRITE_REG(hw, AQ2_FW_INTERFACE_IN_MAC_ADDRESS_REG, mac_addr[0]);
	AQ_WRITE_REG(hw, AQ2_FW_INTERFACE_IN_MAC_ADDRESS_REG + 4u, mac_addr[1]);

	for (reg = AQ2_FW_INTERFACE_IN_SLEEP_PROXY_REG,
	    data = (uint32_t *)&wol, size = sizeof(wol);
	    size >= 4; reg += 4, ++data, size -= 4) {
		AQ_WRITE_REG(hw, reg, *data);
	}

	AQ_WRITE_REG_BIT(hw, AQ2_FW_INTERFACE_IN_LINK_CONTROL_REG,
	    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE, 0,
	    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_SLEEP_PROXY);

	return aq2_fw_wait_shared_ack(hw);
}

static int aq2_fw_get_phy_temp(struct aq_hw *hw, int *temp_c)
{
	struct aq2_phy_health_monitor phy;
	uint32_t data[2];
	uint32_t reg;
	int err;

	if (temp_c == NULL)
		return -EINVAL;

	reg = AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_REG +
	    (uint32_t)offsetof(struct aq2_fw_interface_out_prefix,
	    phy_health_monitor);
	err = aq2_interface_buffer_read(hw, reg, data, sizeof(data));
	if (err != 0)
		return err;

	memcpy(&phy, data, sizeof(phy));
	*temp_c = (int)(int8_t)phy.phy_temperature;
	return 0;
}

static uint32_t aq2_eee_mask_from_caps(const struct aq2_device_link_caps *caps)
{
	uint32_t rate = 0;

	if (caps->eee_10G)
		rate |= AQ_EEE_10G;
	if (caps->eee_5G)
		rate |= AQ_EEE_5G;
	if (caps->eee_2P5G)
		rate |= AQ_EEE_2G5;
	if (caps->eee_1G)
		rate |= AQ_EEE_1G;
	if (caps->eee_100M)
		rate |= AQ_EEE_100M;

	return rate;
}

static uint32_t aq2_eee_mask_from_lkp(const struct aq2_lkp_link_caps *caps)
{
	uint32_t rate = 0;

	if (caps->eee_10G)
		rate |= AQ_EEE_10G;
	if (caps->eee_5G)
		rate |= AQ_EEE_5G;
	if (caps->eee_2P5G)
		rate |= AQ_EEE_2G5;
	if (caps->eee_1G)
		rate |= AQ_EEE_1G;
	if (caps->eee_100M)
		rate |= AQ_EEE_100M;

	return rate;
}

static uint32_t aq2_eee_mask_from_link_options(uint32_t v)
{
	uint32_t rate = 0;

	if (v & AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_10G)
		rate |= AQ_EEE_10G;
	if (v & AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_5G)
		rate |= AQ_EEE_5G;
	if (v & AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_2G5)
		rate |= AQ_EEE_2G5;
	if (v & AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_1G)
		rate |= AQ_EEE_1G;
	if (v & AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_100M)
		rate |= AQ_EEE_100M;

	return rate;
}

static int aq2_fw_set_eee_rate(struct aq_hw *hw, uint32_t rate)
{
	uint32_t v;

	v = AQ_READ_REG(hw, AQ2_FW_INTERFACE_IN_LINK_OPTIONS_REG);
	v &= ~(AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_10G |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_5G |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_2G5 |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_1G |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_100M);

	if (rate & AQ_EEE_10G)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_10G;
	if (rate & AQ_EEE_5G)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_5G;
	if (rate & AQ_EEE_2G5)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_2G5;
	if (rate & AQ_EEE_1G)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_1G;
	if (rate & AQ_EEE_100M)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_100M;

	AQ_WRITE_REG(hw, AQ2_FW_INTERFACE_IN_LINK_OPTIONS_REG, v);
	return aq2_fw_wait_shared_ack(hw);
}

static int aq2_fw_get_eee_rate(struct aq_hw *hw, uint32_t *rate, uint32_t *supported, uint32_t *lp_rate)
{
	struct aq2_device_link_caps dev_caps;
	struct aq2_lkp_link_caps lkp_caps;
	uint32_t v;
	uint32_t reg;
	int err;

	if (rate) {
		v = AQ_READ_REG(hw, AQ2_FW_INTERFACE_IN_LINK_OPTIONS_REG);
		*rate = aq2_eee_mask_from_link_options(v);
	}

	if (supported) {
		reg = AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_REG +
		    (uint32_t)offsetof(struct aq2_fw_interface_out_caps,
		    device_link_caps);
		err = aq2_interface_buffer_read(hw, reg, (uint32_t *)&dev_caps,
		    sizeof(dev_caps));
		if (err == 0)
			*supported = aq2_eee_mask_from_caps(&dev_caps);
		else
			*supported = 0;
	}

	if (lp_rate) {
		reg = AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_REG +
		    (uint32_t)offsetof(struct aq2_fw_interface_out_caps, lkp_link_caps);
		err = aq2_interface_buffer_read(hw, reg, (uint32_t *)&lkp_caps,
		    sizeof(lkp_caps));
		if (err == 0)
			*lp_rate = aq2_eee_mask_from_lkp(&lkp_caps);
		else
			*lp_rate = 0;
	}

	return 0;
}

const struct aq_firmware_ops aq_fw_a2_ops = {
	.reset = aq2_fw_reset,
	.set_mode = aq2_fw_set_mode,
	.get_mode = aq2_fw_get_mode,
	.get_mac_addr = aq2_fw_get_mac_addr,
	.get_stats = aq2_fw_get_stats,
	.led_control = NULL,
	.get_phy_temp = aq2_fw_get_phy_temp,
	.get_cable_len = NULL,
	.get_cable_diag = NULL,
	.set_eee_rate = aq2_fw_set_eee_rate,
	.get_eee_rate = aq2_fw_get_eee_rate,
};
