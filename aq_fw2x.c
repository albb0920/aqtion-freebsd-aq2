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
 * @file aq_fw2x.c
 * Firmware v2.x specific functions.
 * @date 2017.12.11  @author roman.agafonov@aquantia.com
 */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/bitstring.h>
#include <sys/endian.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/types.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/iflib.h>

#include "aq_common.h"
#include "aq_device.h"
#include "aq_hw.h"
#include "aq_hw_llh.h"
#include "aq_hw_llh_internal.h"

#include "aq_fw.h"

#include "aq_dbg.h"

typedef enum {
    CAPS_LO_10BASET_HD = 0x00,
    CAPS_LO_10BASET_FD,
    CAPS_LO_100BASETX_HD,
    CAPS_LO_100BASET4_HD,
    CAPS_LO_100BASET2_HD,
    CAPS_LO_100BASETX_FD,
    CAPS_LO_100BASET2_FD,
    CAPS_LO_1000BASET_HD,
    CAPS_LO_1000BASET_FD,
    CAPS_LO_2P5GBASET_FD,
    CAPS_LO_5GBASET_FD,
    CAPS_LO_10GBASET_FD,
} fw2x_caps_lo;

typedef enum {
    CAPS_HI_RESERVED1 = 0x00,
    CAPS_HI_10BASET_EEE,
    CAPS_HI_RESERVED2,
    CAPS_HI_PAUSE,
    CAPS_HI_ASYMMETRIC_PAUSE,
    CAPS_HI_100BASETX_EEE,
    CAPS_HI_RESERVED3,
    CAPS_HI_RESERVED4,
    CAPS_HI_1000BASET_FD_EEE,
    CAPS_HI_2P5GBASET_FD_EEE,
    CAPS_HI_5GBASET_FD_EEE,
    CAPS_HI_10GBASET_FD_EEE,
    CAPS_HI_RESERVED5,
    CAPS_HI_RESERVED6,
    CAPS_HI_RESERVED7,
    CAPS_HI_RESERVED8,
    CAPS_HI_RESERVED9,
    CAPS_HI_CABLE_DIAG,
    CAPS_HI_TEMPERATURE,
    CAPS_HI_DOWNSHIFT,
    CAPS_HI_PTP_AVB_EN,
    CAPS_HI_MEDIA_DETECT,
    CAPS_HI_LINK_DROP,
    CAPS_HI_SLEEP_PROXY,
    CAPS_HI_WOL,
    CAPS_HI_MAC_STOP,
    CAPS_HI_EXT_LOOPBACK,
    CAPS_HI_INT_LOOPBACK,
    CAPS_HI_EFUSE_AGENT,
    CAPS_HI_WOL_TIMER,
    CAPS_HI_STATISTICS,
    CAPS_HI_TRANSACTION_ID,
} fw2x_caps_hi;

typedef enum aq_fw2x_rate
{
    FW2X_RATE_100M = 0x20,
    FW2X_RATE_1G = 0x100,
    FW2X_RATE_2G5 = 0x200,
    FW2X_RATE_5G = 0x400,
    FW2X_RATE_10G = 0x800,
} aq_fw2x_rate;


typedef struct fw2x_msm_statistics
{
    uint32_t uprc;
    uint32_t mprc;
    uint32_t bprc;
    uint32_t erpt;
    uint32_t uptc;
    uint32_t mptc;
    uint32_t bptc;
    uint32_t erpr;
    uint32_t mbtc;
    uint32_t bbtc;
    uint32_t mbrc;
    uint32_t bbrc;
    uint32_t ubrc;
    uint32_t ubtc;
    uint32_t ptc;
    uint32_t prc;
} fw2x_msm_statistics;

typedef struct fw2x_phy_cable_diag_data
{
    u32 lane_data[4];
} fw2x_phy_cable_diag_data;

typedef struct fw2x_capabilities {
    u32 caps_lo;
    u32 caps_hi;
} fw2x_capabilities;

typedef struct fw2x_mailbox // struct fwHostInterface
{
    u32 version;
    u32 transaction_id;
    s32 error;
    fw2x_msm_statistics msm; // msmStatistics_t msm;
    u16 phy_h_bit;
    u16 phy_fault_code;
    s16 phy_temperature;
    u8 cable_len;
    u8 reserved1;
    fw2x_phy_cable_diag_data diag_data;
    u32 reserved[8];

    fw2x_capabilities caps;

    /* ... */
} fw2x_mailbox;

struct __packed fw2x_offload_ip_info {
    u8 v4_local_addr_count;
    u8 v4_addr_count;
    u8 v6_local_addr_count;
    u8 v6_addr_count;
    u32 v4_addr;
    u32 v4_prefix;
    u32 v6_addr;
    u32 v6_prefix;
};

struct __packed fw2x_offload_port_info {
    u16 udp_port_count;
    u16 tcp_port_count;
    u32 udp_port;
    u32 tcp_port;
};

struct __packed fw2x_offload_ka_info {
    u16 v4_ka_count;
    u16 v6_ka_count;
    u32 retry_count;
    u32 retry_interval;
    u32 v4_ka;
    u32 v6_ka;
};

struct __packed fw2x_offload_rr_info {
    u32 rr_count;
    u32 rr_buf_len;
    u32 rr_id_x;
    u32 rr_buf;
};

struct __packed fw2x_offload_info {
    u32 version;
    u32 len;
    u8 mac_addr[6];
    u8 reserved[2];
    struct fw2x_offload_ip_info ips;
    struct fw2x_offload_port_info ports;
    struct fw2x_offload_ka_info kas;
    struct fw2x_offload_rr_info rrs;
};

struct __packed fw2x_rpc_msg {
    u32 msg_id;
    struct fw2x_offload_info offloads;
};

struct fw2x_rpc_tid {
    union {
        u32 val;
        struct {
            u16 tid;
            u16 len;
        };
    };
};

struct __packed fw2x_mbox_header {
    u32 version;
    u32 transaction_id;
    u32 error;
};

struct __packed fw2x_stats {
    u32 uprc;
    u32 mprc;
    u32 bprc;
    u32 erpt;
    u32 uptc;
    u32 mptc;
    u32 bptc;
    u32 erpr;
    u32 mbtc;
    u32 bbtc;
    u32 mbrc;
    u32 bbrc;
    u32 ubrc;
    u32 ubtc;
    u32 dpc;
};

struct __packed fw2x_ptp_offset {
    u16 ingress_100;
    u16 egress_100;
    u16 ingress_1000;
    u16 egress_1000;
    u16 ingress_2500;
    u16 egress_2500;
    u16 ingress_5000;
    u16 egress_5000;
    u16 ingress_10000;
    u16 egress_10000;
};

struct __packed fw2x_info {
    u8 reserved[6];
    u16 phy_fault_code;
    u16 phy_temperature;
    u8 cable_len;
    u8 reserved1;
    u8 cable_diag_data[16];
    struct fw2x_ptp_offset ptp_offset;
    u8 reserved2[12];
    u32 caps_lo;
    u32 caps_hi;
    u32 reserved_datapath;
    u32 reserved3[7];
    u32 reserved_simpleresp[3];
    u32 reserved_linkstat[7];
    u32 reserved_wakes_count;
    u32 reserved_eee_stat[12];
    u32 tx_stuck_cnt;
    u32 setting_address;
    u32 setting_length;
    u32 caps_ex;
};

struct __packed fw2x_mbox_full {
    struct fw2x_mbox_header header;
    struct fw2x_stats stats;
    struct fw2x_info info;
};

struct __packed fw2x_settings {
    u32 mtu;
    u32 downshift_retry_count;
    u32 link_pause_frame_quanta_100m;
    u32 link_pause_frame_threshold_100m;
    u32 link_pause_frame_quanta_1g;
    u32 link_pause_frame_threshold_1g;
    u32 link_pause_frame_quanta_2p5g;
    u32 link_pause_frame_threshold_2p5g;
    u32 link_pause_frame_quanta_5g;
    u32 link_pause_frame_threshold_5g;
    u32 link_pause_frame_quanta_10g;
    u32 link_pause_frame_threshold_10g;
    u32 pfc_quanta_class_0;
    u32 pfc_threshold_class_0;
    u32 pfc_quanta_class_1;
    u32 pfc_threshold_class_1;
    u32 pfc_quanta_class_2;
    u32 pfc_threshold_class_2;
    u32 pfc_quanta_class_3;
    u32 pfc_threshold_class_3;
    u32 pfc_quanta_class_4;
    u32 pfc_threshold_class_4;
    u32 pfc_quanta_class_5;
    u32 pfc_threshold_class_5;
    u32 pfc_quanta_class_6;
    u32 pfc_threshold_class_6;
    u32 pfc_quanta_class_7;
    u32 pfc_threshold_class_7;
    u32 eee_link_down_timeout;
    u32 eee_link_up_timeout;
    u32 eee_max_link_drops;
    u32 eee_rates_mask;
    u32 wake_timer;
    u32 thermal_shutdown_off_temp;
    u32 thermal_shutdown_warning_temp;
    u32 thermal_shutdown_cold_temp;
    u32 msm_options;
    u32 dac_cable_serdes_modes;
    u32 media_detect;
};


// EEE caps
#define FW2X_FW_CAP_EEE_100M (1ULL << (32 + CAPS_HI_100BASETX_EEE))
#define FW2X_FW_CAP_EEE_1G   (1ULL << (32 + CAPS_HI_1000BASET_FD_EEE))
#define FW2X_FW_CAP_EEE_2G5  (1ULL << (32 + CAPS_HI_2P5GBASET_FD_EEE))
#define FW2X_FW_CAP_EEE_5G   (1ULL << (32 + CAPS_HI_5GBASET_FD_EEE))
#define FW2X_FW_CAP_EEE_10G  (1ULL << (32 + CAPS_HI_10GBASET_FD_EEE))

// Flow Control
#define FW2X_FW_CAP_PAUSE      (1ULL << (32 + CAPS_HI_PAUSE))
#define FW2X_FW_CAP_ASYM_PAUSE (1ULL << (32 + CAPS_HI_ASYMMETRIC_PAUSE))

// Link Drop
#define FW2X_CAP_LINK_DROP  (1ull << (32 + CAPS_HI_LINK_DROP))
#define FW2X_CAP_SLEEP_PROXY (1ull << (32 + CAPS_HI_SLEEP_PROXY))
#define FW2X_CAP_WOL        (1ull << (32 + CAPS_HI_WOL))
#define FW2X_CAP_DOWNSHIFT  (1ull << (32 + CAPS_HI_DOWNSHIFT))
#define FW2X_CAP_MEDIA_DETECT (1ull << (32 + CAPS_HI_MEDIA_DETECT))

// MSM Statistics
#define FW2X_CAP_STATISTICS (1ull << (32 + CAPS_HI_STATISTICS))


#define FW2X_RATE_MASK  (FW2X_RATE_100M | FW2X_RATE_1G | FW2X_RATE_2G5 | FW2X_RATE_5G | FW2X_RATE_10G)
#define FW2X_EEE_MASK  (FW2X_FW_CAP_EEE_100M | FW2X_FW_CAP_EEE_1G | FW2X_FW_CAP_EEE_2G5 | FW2X_FW_CAP_EEE_5G | FW2X_FW_CAP_EEE_10G)

#define FW2X_CTRL_WAKE_ON_LINK     BIT(16)
#define FW2X_CTRL_LINK_DROP        BIT(22)
#define FW2X_CTRL_SLEEP_PROXY      BIT(23)
#define FW2X_CTRL_WOL              BIT(24)
#define FW2X_CTRL_DOWNSHIFT        BIT(19)
#define FW2X_CTRL_EXT_LOOPBACK     BIT(26)
#define FW2X_CTRL_INT_LOOPBACK     BIT(27)

#define FW2X_MPI_LED_ADDR           0x31c
#define FW2X_MPI_RPC_ADDR           0x334
#define FW2X_RPC_CONTROL_ADDR       0x338
#define FW2X_RPC_STATE_ADDR         0x33c
#define FW2X_MPI_CONTROL_ADDR       0x368
#define FW2X_MPI_STATE_ADDR         0x370
#define FW2X_MPI_CONTROL2_ADDR      0x36c
#define FW2X_MPI_STATE2_ADDR        0x374

#define FW2X_FW_MIN_VER_LED 0x03010026U

#define FW2X_LED_BLINK    0x2U
#define FW2X_LED_DEFAULT  0x0U

// Firmware v2-3.x specific functions.
//@{
int fw2x_reset(struct aq_hw* hw);

int fw2x_set_mode(struct aq_hw* hw, enum aq_hw_fw_mpi_state_e mode, aq_fw_link_speed_t speed);
int fw2x_get_mode(struct aq_hw* hw, enum aq_hw_fw_mpi_state_e* mode, aq_fw_link_speed_t* speed, aq_fw_link_fc_t* fc);

int fw2x_get_mac_addr(struct aq_hw* hw, u8* mac);
int fw2x_get_stats(struct aq_hw* hw, struct aq_hw_stats_s* stats);
int fw2x_get_phy_temp(struct aq_hw* hw, int *temp_c);
int fw2x_get_cable_len(struct aq_hw* hw, u8 *len);
int fw2x_get_cable_diag(struct aq_hw* hw, u32 lane_data[4]);
int fw2x_set_eee_rate(struct aq_hw* hw, u32 rate);
int fw2x_get_eee_rate(struct aq_hw* hw, u32 *rate, u32 *supported, u32 *lp_rate);
//@}



static u64 read64_(struct aq_hw* hw, u32 addr)
{
    u64 lo = AQ_READ_REG(hw, addr);
    u64 hi = AQ_READ_REG(hw, addr + 4);
    return (lo | (hi << 32));
}

static uint64_t get_mpi_ctrl_(struct aq_hw* hw)
{
    return read64_(hw, FW2X_MPI_CONTROL_ADDR);
}

static uint64_t get_mpi_state_(struct aq_hw* hw)
{
    return read64_(hw, FW2X_MPI_STATE_ADDR);
}

static void set_mpi_ctrl_(struct aq_hw* hw, u64 value)
{
    AQ_WRITE_REG(hw, FW2X_MPI_CONTROL_ADDR, (u32)value);
    AQ_WRITE_REG(hw, FW2X_MPI_CONTROL_ADDR + 4, (u32)(value >> 32));
}

static u32 fw2x_caps_to_eee_mask_(u64 caps)
{
    u32 rate = 0;

    if (caps & FW2X_FW_CAP_EEE_10G)
        rate |= AQ_EEE_10G;
    if (caps & FW2X_FW_CAP_EEE_5G)
        rate |= AQ_EEE_5G;
    if (caps & FW2X_FW_CAP_EEE_2G5)
        rate |= AQ_EEE_2G5;
    if (caps & FW2X_FW_CAP_EEE_1G)
        rate |= AQ_EEE_1G;
    if (caps & FW2X_FW_CAP_EEE_100M)
        rate |= AQ_EEE_100M;

    return rate;
}

static u64 fw2x_eee_mask_to_caps_(u32 rate)
{
    u64 caps = 0;

    if (rate & AQ_EEE_10G)
        caps |= FW2X_FW_CAP_EEE_10G;
    if (rate & AQ_EEE_5G)
        caps |= FW2X_FW_CAP_EEE_5G;
    if (rate & AQ_EEE_2G5)
        caps |= FW2X_FW_CAP_EEE_2G5;
    if (rate & AQ_EEE_1G)
        caps |= FW2X_FW_CAP_EEE_1G;
    if (rate & AQ_EEE_100M)
        caps |= FW2X_FW_CAP_EEE_100M;

    return caps;
}

int fw2x_read_settings_addr(struct aq_hw *hw)
{
    u32 addr = 0;
    u32 len = 0;
    u32 offset;
    int err;

    if (hw->mbox_addr == 0)
        return (-ENOTSUP);
    offset = offsetof(struct fw2x_mbox_full, info.setting_address);
    err = aq_hw_fw_downld_dwords(hw, hw->mbox_addr + offset, &addr, 1);
    if (err != 0)
        return (err);
    offset = offsetof(struct fw2x_mbox_full, info.setting_length);
    err = aq_hw_fw_downld_dwords(hw, hw->mbox_addr + offset, &len, 1);
    if (err != 0)
        return (err);

    if (addr == 0 || addr == 0xffffffffU || (addr & 0x3U) != 0 ||
        len < sizeof(struct fw2x_settings)) {
        hw->settings_addr = 0;
        return (-ENOTSUP);
    }

    hw->settings_addr = addr;
    return (0);
}

static int fw2x_write_settings_dwords(struct aq_hw *hw, u32 offset,
    const u32 *p, u32 cnt)
{
    if (hw->settings_addr == 0)
        return (-ENOTSUP);
    return aq_hw_fw_upload_dwords(hw, hw->settings_addr + offset, p, cnt);
}

static int fw2x_rpc_call(struct aq_hw *hw, const void *buf, u32 len)
{
    struct fw2x_rpc_tid sw;
    u32 dword_cnt;
    int err = 0;

    if (len > AQ_FW_RPC_MAX)
        return (-EINVAL);

    if (buf && len != 0) {
        memcpy(hw->rpc_buf, buf, len);
        hw->rpc_len = (u16)len;
    }

    if (hw->rpc_addr == 0)
        return (-ENOTSUP);

    dword_cnt = (len + sizeof(u32) - 1U) / sizeof(u32);
    if (dword_cnt != 0) {
        err = aq_hw_fw_upload_dwords(hw, hw->rpc_addr,
            (const u32 *)(const void *)hw->rpc_buf, dword_cnt);
        if (err != 0)
            return (err);
    }

    hw->rpc_tid++;
    sw.tid = hw->rpc_tid;
    sw.len = (u16)len;
    AQ_WRITE_REG(hw, FW2X_RPC_CONTROL_ADDR, sw.val);
    return (0);
}

int fw2x_set_downshift(struct aq_hw *hw, u32 counter)
{
    u32 mpi_opts;
    u32 offset;
    int err;

    if ((hw->fw_caps & FW2X_CAP_DOWNSHIFT) == 0)
        return (-ENOTSUP);
    offset = offsetof(struct fw2x_settings, downshift_retry_count);
    err = fw2x_write_settings_dwords(hw, offset, &counter, 1);
    if (err != 0)
        return (err);

    mpi_opts = AQ_READ_REG(hw, FW2X_MPI_CONTROL2_ADDR);
    if (counter)
        mpi_opts |= FW2X_CTRL_DOWNSHIFT;
    else
        mpi_opts &= ~FW2X_CTRL_DOWNSHIFT;
    AQ_WRITE_REG(hw, FW2X_MPI_CONTROL2_ADDR, mpi_opts);
    return (0);
}

int fw2x_set_media_detect(struct aq_hw *hw, bool enable)
{
    u32 val = enable ? 1U : 0U;
    u32 offset;

    if ((hw->fw_caps & FW2X_CAP_MEDIA_DETECT) == 0)
        return (-ENOTSUP);
    offset = offsetof(struct fw2x_settings, media_detect);
    return fw2x_write_settings_dwords(hw, offset, &val, 1);
}

int fw2x_set_loopback(struct aq_hw *hw, int mode)
{
    u32 mpi_opts;

    mpi_opts = AQ_READ_REG(hw, FW2X_MPI_CONTROL2_ADDR);
    switch (mode) {
    case 0:
        mpi_opts &= ~(FW2X_CTRL_INT_LOOPBACK | FW2X_CTRL_EXT_LOOPBACK);
        break;
    case 1:
        mpi_opts |= FW2X_CTRL_INT_LOOPBACK;
        mpi_opts &= ~FW2X_CTRL_EXT_LOOPBACK;
        break;
    case 2:
        mpi_opts |= FW2X_CTRL_EXT_LOOPBACK;
        mpi_opts &= ~FW2X_CTRL_INT_LOOPBACK;
        break;
    default:
        return (-EINVAL);
    }
    AQ_WRITE_REG(hw, FW2X_MPI_CONTROL2_ADDR, mpi_opts);
    return (0);
}

static u32 fw2x_rpc_state_get(struct aq_hw *hw)
{
    return AQ_READ_REG(hw, FW2X_RPC_STATE_ADDR);
}

static int fw2x_rpc_wait(struct aq_hw *hw, u32 *fw_len)
{
    struct fw2x_rpc_tid sw;
    struct fw2x_rpc_tid fw;
    int err = 0;
    u32 dword_cnt;

    do {
        sw.val = AQ_READ_REG(hw, FW2X_RPC_CONTROL_ADDR);
        hw->rpc_tid = sw.tid;

        AQ_HW_WAIT_FOR(((fw.val = fw2x_rpc_state_get(hw)),
            sw.tid == fw.tid), 1000U, 100000U);
        if (err < 0)
            return (-EIO);

        if (fw.len == 0xFFFFU) {
            err = fw2x_rpc_call(hw, NULL, sw.len);
            if (err != 0)
                return (err);
        }
    } while (sw.tid != fw.tid || fw.len == 0xFFFFU);

    if (fw.len > AQ_FW_RPC_MAX)
        return (-EINVAL);
    if (fw.len != 0) {
        dword_cnt = (fw.len + sizeof(u32) - 1U) / sizeof(u32);
        err = aq_hw_fw_downld_dwords(hw, hw->rpc_addr,
            (u32 *)(void *)hw->rpc_buf, dword_cnt);
        if (err != 0)
            return (err);
    }
    if (fw_len)
        *fw_len = fw.len;
    return (0);
}


int fw2x_reset(struct aq_hw* hw)
{
    fw2x_capabilities caps = {0};
    AQ_DBG_ENTER();
    int err = aq_hw_fw_downld_dwords(hw, hw->mbox_addr + offsetof(fw2x_mailbox, caps), (u32*)&caps, sizeof caps/sizeof(u32));
    if (err == EOK) {
        hw->fw_caps = caps.caps_lo | ((u64)caps.caps_hi << 32);
        trace(dbg_init, "fw2x> F/W capabilities mask = %llx", (unsigned long long)hw->fw_caps);
    } else {
        trace_error(dbg_init, "fw2x> can't get F/W capabilities mask, error %d", err);
    }

	AQ_DBG_EXIT(EOK);
	return (EOK);
}


static
aq_fw2x_rate link_speed_mask_to_fw2x_(u32 speed)
{
    u32 rate = 0;

    AQ_DBG_ENTER();
    if (speed & aq_fw_10G)
        rate |= FW2X_RATE_10G;

    if (speed & aq_fw_5G)
        rate |= FW2X_RATE_5G;

    if (speed & aq_fw_2G5)
        rate |= FW2X_RATE_2G5;

    if (speed & aq_fw_1G)
        rate |= FW2X_RATE_1G;

    if (speed & aq_fw_100M)
        rate |= FW2X_RATE_100M;

    AQ_DBG_EXIT(rate);
    return ((aq_fw2x_rate)rate);
}


int fw2x_set_mode(struct aq_hw* hw, enum aq_hw_fw_mpi_state_e mode, aq_fw_link_speed_t speed)
{
    u64 mpi_ctrl = get_mpi_ctrl_(hw);
    
    AQ_DBG_ENTERA("speed=%d", speed);
    switch (mode) {
    case MPI_INIT:
        mpi_ctrl &= ~FW2X_RATE_MASK;
        mpi_ctrl |= link_speed_mask_to_fw2x_(speed);
        mpi_ctrl &= ~FW2X_CAP_LINK_DROP;
        mpi_ctrl &= ~FW2X_EEE_MASK;
        mpi_ctrl |= fw2x_eee_mask_to_caps_(hw->eee_rate);
        if (hw->fc.fc_rx)
            mpi_ctrl |= FW2X_FW_CAP_PAUSE;
        if (hw->fc.fc_tx)
            mpi_ctrl |= FW2X_FW_CAP_ASYM_PAUSE;
        break;

    case MPI_DEINIT:
        mpi_ctrl &= ~FW2X_RATE_MASK;
        mpi_ctrl &= ~(FW2X_FW_CAP_PAUSE | FW2X_FW_CAP_ASYM_PAUSE);
        break;

    default:
        trace_error(dbg_init, "fw2x> unknown MPI state %d", mode);
        return (-EINVAL);
    }

    set_mpi_ctrl_(hw, mpi_ctrl);
    AQ_DBG_EXIT(EOK);
    return (EOK);
}

int fw2x_get_mode(struct aq_hw* hw, enum aq_hw_fw_mpi_state_e* mode, aq_fw_link_speed_t* link_speed, aq_fw_link_fc_t* fc)
{
    u64 mpi_state = get_mpi_state_(hw);
    u32 rates = mpi_state & FW2X_RATE_MASK;

 //   AQ_DBG_ENTER();

    if (mode) {
        u64 mpi_ctrl = get_mpi_ctrl_(hw);
        if (mpi_ctrl & FW2X_RATE_MASK)
            *mode = MPI_INIT;
        else
            *mode = MPI_DEINIT;
    }

    aq_fw_link_speed_t speed = aq_fw_none;
    
    if (rates & FW2X_RATE_10G)
        speed = aq_fw_10G;
    else if (rates & FW2X_RATE_5G)
        speed = aq_fw_5G;
    else if (rates & FW2X_RATE_2G5)
        speed = aq_fw_2G5;
    else if (rates & FW2X_RATE_1G)
        speed = aq_fw_1G;
    else if (rates & FW2X_RATE_100M)
        speed = aq_fw_100M;

    if (link_speed)
        *link_speed = speed;

    *fc = (mpi_state & (FW2X_FW_CAP_PAUSE | FW2X_FW_CAP_ASYM_PAUSE)) >> (32 + CAPS_HI_PAUSE);


//    AQ_DBG_EXIT(0);
    return (EOK);
}


int fw2x_get_mac_addr(struct aq_hw* hw, u8* mac)
{
    int err = -EFAULT;
    u32 mac_addr[2];

    AQ_DBG_ENTER();

    u32 efuse_shadow_addr = AQ_READ_REG(hw, 0x364);
    if (efuse_shadow_addr == 0) {
        trace_error(dbg_init, "couldn't read eFUSE Shadow Address");
        AQ_DBG_EXIT(-EFAULT);
        return (-EFAULT);
    }

    err = aq_hw_fw_downld_dwords(hw, efuse_shadow_addr + (40 * 4),
        mac_addr, ARRAY_SIZE(mac_addr));
    if (err < 0) {
        mac_addr[0] = 0;
        mac_addr[1] = 0;
        AQ_DBG_EXIT(err);
        return (err);
    }

    mac_addr[0] = bswap32(mac_addr[0]);
    mac_addr[1] = bswap32(mac_addr[1]);

    memcpy(mac, (u8*)mac_addr, ETH_MAC_LEN);

    AQ_DBG_EXIT(EOK);
    return (EOK);
}

static inline
void fw2x_stats_to_fw_stats_(struct aq_hw_stats_s* dst, const fw2x_msm_statistics* src)
{
    dst->uprc = src->uprc;
    dst->mprc = src->mprc;
    dst->bprc = src->bprc;
    dst->erpt = src->erpt;
    dst->uptc = src->uptc;
    dst->mptc = src->mptc;
    dst->bptc = src->bptc;
    dst->erpr = src->erpr;
    dst->mbtc = src->mbtc;
    dst->bbtc = src->bbtc;
    dst->mbrc = src->mbrc;
    dst->bbrc = src->bbrc;
    dst->ubrc = src->ubrc;
    dst->ubtc = src->ubtc;
    dst->ptc = src->ptc;
    dst->prc = src->prc;
}


static bool toggle_mpi_ctrl_and_wait_(struct aq_hw* hw, u64 mask, u32 timeout_ms, u32 try_count)
{
    u64 ctrl = get_mpi_ctrl_(hw);
    u64 state = get_mpi_state_(hw);

 //   AQ_DBG_ENTER();
    // First, check that control and state values are consistent
    if ((ctrl & mask) != (state & mask)) {
        trace_warn(dbg_fw, "fw2x> MPI control (%#llx) and state (%#llx) are not consistent for mask %#llx!",
            (unsigned long long)ctrl, (unsigned long long)state, (unsigned long long)mask);
		AQ_DBG_EXIT(false);
        return (false);
    }

    // Invert bits (toggle) in control register
    ctrl ^= mask;
    set_mpi_ctrl_(hw, ctrl);

    // Clear all bits except masked
    ctrl &= mask;

    // Wait for FW reflecting change in state register
    while (try_count-- != 0) {
        if ((get_mpi_state_(hw) & mask) == ctrl)
		{
//			AQ_DBG_EXIT(true);
            return (true);
		}
        msec_delay(timeout_ms);
    }

    trace_detail(dbg_fw, "f/w2x> timeout while waiting for response in state register for bit %#llx!", (unsigned long long)mask);
 //   AQ_DBG_EXIT(false);
    return (false);
}


int fw2x_get_stats(struct aq_hw* hw, struct aq_hw_stats_s* stats)
{
    int err = 0;
    fw2x_msm_statistics fw2x_stats = {0};

//    AQ_DBG_ENTER();

    if ((hw->fw_caps & FW2X_CAP_STATISTICS) == 0) {
        trace_warn(dbg_fw, "fw2x> statistics not supported by F/W");
        return (-ENOTSUP);
    }

    // Say to F/W to update the statistics
    if (!toggle_mpi_ctrl_and_wait_(hw, FW2X_CAP_STATISTICS, 1, 25)) {
        trace_error(dbg_fw, "fw2x> statistics update timeout");
		AQ_DBG_EXIT(-ETIME);
        return (-ETIME);
    }

    err = aq_hw_fw_downld_dwords(hw, hw->mbox_addr + offsetof(fw2x_mailbox, msm),
        (u32*)&fw2x_stats, sizeof fw2x_stats/sizeof(u32));

    fw2x_stats_to_fw_stats_(stats, &fw2x_stats);

    if (err != EOK)
        trace_error(dbg_fw, "fw2x> download statistics data FAILED, error %d", err);

//    AQ_DBG_EXIT(err);
    return (err);
}

int fw2x_set_eee_rate(struct aq_hw* hw, u32 rate)
{
    u64 mpi_ctrl = get_mpi_ctrl_(hw);

    mpi_ctrl &= ~FW2X_EEE_MASK;
    mpi_ctrl |= fw2x_eee_mask_to_caps_(rate);
    set_mpi_ctrl_(hw, mpi_ctrl);
    return (EOK);
}

int fw2x_get_eee_rate(struct aq_hw* hw, u32 *rate, u32 *supported,
    u32 *lp_rate)
{
    u64 mpi_state = get_mpi_state_(hw);

    if (supported)
        *supported = fw2x_caps_to_eee_mask_(hw->fw_caps);
    if (rate)
        *rate = fw2x_caps_to_eee_mask_(mpi_state);
    if (lp_rate)
        *lp_rate = 0;

    return (EOK);
}

int fw2x_set_wol(struct aq_hw *hw, u32 wol_flags, const u8 *mac)
{
    u32 mpi_ctrl2;
    struct fw2x_rpc_msg msg;
    u32 rpc_size;
    int err = 0;

    if (hw->rpc_addr == 0)
        return (-ENOTSUP);

    mpi_ctrl2 = AQ_READ_REG(hw, FW2X_MPI_CONTROL2_ADDR);

    if (wol_flags & AQ_WOL_PHY) {
        AQ_WRITE_REG(hw, FW2X_MPI_CONTROL2_ADDR,
            mpi_ctrl2 | FW2X_CTRL_LINK_DROP);
        AQ_HW_WAIT_FOR((AQ_READ_REG(hw, FW2X_MPI_STATE2_ADDR) &
            FW2X_CTRL_LINK_DROP) != 0, 1000, 100000);
        if (err < 0)
            return (-EIO);
        mpi_ctrl2 &= ~FW2X_CTRL_LINK_DROP;
        mpi_ctrl2 |= FW2X_CTRL_WAKE_ON_LINK;
    } else {
        mpi_ctrl2 &= ~FW2X_CTRL_WAKE_ON_LINK;
    }

    if (wol_flags & AQ_WOL_MAGIC) {
        mpi_ctrl2 |= FW2X_CTRL_SLEEP_PROXY | FW2X_CTRL_WOL;
        err = fw2x_rpc_wait(hw, NULL);
        if (err != 0)
            return (err);
        memset(&msg, 0, sizeof(msg));
        msg.offloads.len = sizeof(msg.offloads);
        memcpy(msg.offloads.mac_addr, mac, 6);
        rpc_size = offsetof(struct fw2x_rpc_msg, offloads) +
            sizeof(msg.offloads);
        err = fw2x_rpc_call(hw, &msg, rpc_size);
        if (err != 0)
            return (err);
    } else {
        mpi_ctrl2 &= ~(FW2X_CTRL_SLEEP_PROXY | FW2X_CTRL_WOL);
    }

    AQ_WRITE_REG(hw, FW2X_MPI_CONTROL2_ADDR, mpi_ctrl2);
    return (EOK);
}

int fw2x_get_phy_temp(struct aq_hw* hw, int *temp_c)
{
    u32 word = 0;
    int err;

    if (temp_c == NULL)
        return (-EINVAL);

    err = aq_hw_fw_downld_dwords(hw,
        hw->mbox_addr + offsetof(fw2x_mailbox, phy_temperature),
        &word, 1);
    if (err < 0)
        return (err);

    word = le32toh(word);
    *temp_c = (int)(int16_t)(word & 0xffffu);
    return (EOK);
}

int fw2x_get_cable_len(struct aq_hw* hw, u8 *len)
{
    u32 word = 0;
    int err;

    if (len == NULL)
        return (-EINVAL);

    err = aq_hw_fw_downld_dwords(hw,
        hw->mbox_addr + offsetof(fw2x_mailbox, phy_temperature),
        &word, 1);
    if (err < 0)
        return (err);

    word = le32toh(word);
    *len = (u8)((word >> 16) & 0xffu);
    return (EOK);
}

int fw2x_get_cable_diag(struct aq_hw* hw, u32 lane_data[4])
{
    int err;

    if (lane_data == NULL)
        return (-EINVAL);

    err = aq_hw_fw_downld_dwords(hw,
        hw->mbox_addr + offsetof(fw2x_mailbox, diag_data),
        lane_data, 4);
    if (err < 0)
        return (err);

    lane_data[0] = le32toh(lane_data[0]);
    lane_data[1] = le32toh(lane_data[1]);
    lane_data[2] = le32toh(lane_data[2]);
    lane_data[3] = le32toh(lane_data[3]);
    return (EOK);
}

static int fw2x_led_control(struct aq_hw* hw, u32 onoff)
{
    int err = 0;

    AQ_DBG_ENTER();

    aq_hw_fw_version ver_expected = { .raw = FW2X_FW_MIN_VER_LED};
    if (aq_hw_ver_match(&ver_expected, &hw->fw_version))
        AQ_WRITE_REG(hw, FW2X_MPI_LED_ADDR, (onoff)?
					    ((FW2X_LED_BLINK) | (FW2X_LED_BLINK << 2) | (FW2X_LED_BLINK << 4)):
					    (FW2X_LED_DEFAULT));

    AQ_DBG_EXIT(err);
    return (err);
}

struct aq_firmware_ops aq_fw2x_ops =
{
    .reset = fw2x_reset,

    .set_mode = fw2x_set_mode,
    .get_mode = fw2x_get_mode,

    .get_mac_addr = fw2x_get_mac_addr,
    .get_stats = fw2x_get_stats,

    .led_control = fw2x_led_control,
    .get_phy_temp = fw2x_get_phy_temp,
    .get_cable_len = fw2x_get_cable_len,
    .get_cable_diag = fw2x_get_cable_diag,
    .set_eee_rate = fw2x_set_eee_rate,
    .get_eee_rate = fw2x_get_eee_rate,
};
