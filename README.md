# FreeBSD driver

Atlantic driver for FreeBSD

## Interrupt moderation

The driver exposes per-device interrupt moderation controls under
`dev.aq.N`:

```
sysctl dev.aq.0.itr_mode=-1   # auto
sysctl dev.aq.0.itr_mode=1    # manual
sysctl dev.aq.0.itr_tx=128
sysctl dev.aq.0.itr_rx=96
sysctl dev.aq.0.itr_mode=0    # off
```

Modes:
- `0` disables interrupt moderation.
- `1` enables manual interrupt moderation using `itr_tx` and `itr_rx`.
- `-1` selects the built-in automatic profile from link speed.

`itr_tx` and `itr_rx` are manual maximum delay values in microseconds and
accept `0..1022`.

On A0 hardware the manual TX/RX settings are coupled internally, so writing
either `itr_tx` or `itr_rx` updates both values.

## RX filter sysctls

The driver exposes software-managed RX filter tables under `dev.aq.N.rx_filter`.
These allow queue steering and simple drop rules using the hardware filter
blocks (similar to `ethtool -N` on Linux).

L2 ethertype filters:

```
sysctl dev.aq.0.rx_filter.l2.f0="enable=1,ethertype=0x88e5,queue=2,prio_en=0,prio=0"
```

VLAN filters (must already be an active VLAN on the interface):

```
sysctl dev.aq.0.rx_filter.vlan.f0="enable=1,vlan=100,queue=3"
```

L3/L4 filters (IPv4 example):

```
sysctl dev.aq.0.rx_filter.l3l4.f0="enable=1,ipv6=0,proto=tcp,src=0x0,dst=0x0,sport=0,dport=443,action=host,queue=1"
```

Notes:
- `queue=-1` means no queue steering.
- IPv6 addresses are 32 hex digits in `src6`/`dst6` (no colons).
- IPv6 filters use 4 slots; locations must be 0 or 4.
- L3/L4 filters are not available on AQ2 hardware (will return ENOTSUP).

## Wake-on-LAN

Magic packet WoL is controlled by standard interface capabilities.
Link-change wake (WAKE_PHY) can be enabled via:

```
sysctl dev.aq.0.wol_phy=1
```

You can also set a combined mask (magic|phy):

```
sysctl dev.aq.0.wol_mask=3
```

## Downshift control

This is available on AQ2 and FW2x devices:

```
sysctl dev.aq.0.downshift=3
```

## FW2x-only controls

These are only available on FW2x devices:

```
sysctl dev.aq.0.media_detect=1
sysctl dev.aq.0.loopback=1   # 0=off,1=int,2=ext
```

## Accumulated Statistics

Available counters depend on device family and firmware interface version.

For AQ2 (AQC113/AQC114/AQC115/AQC116) NICs, you can find your firmware
interface version with:
```
sysctl dev.aq.N.fw_iface_ver
```

All `dev.aq.N.mac.*` fields are always present in sysctl.

When a field is not provided by the firmware interface, it stays `0`.

### Counters availability

Legend:
- `Y`: counter is populated
- `N`: counter is not populated

| sysctl field         | meaning                           | AQ1 | AQ2 A0 | AQ2 B0 |
|----------------------|-----------------------------------|-----|--------|--------|
| `good_pkts_rcvd`     | RX good packets (uni+multi+bcast) | Y   | Y      | Y      |
| `ucast_pkts_rcvd`    | RX unicast packets                | Y   | Y      | Y      |
| `mcast_pkts_rcvd`    | RX multicast packets              | Y   | Y      | Y      |
| `bcast_pkts_rcvd`    | RX broadcast packets              | Y   | Y      | Y      |
| `pause_frames_rcvd`  | RX Ethernet pause frames          | N   | N      | Y      |
| `rsc_pkts_rcvd`      | RX coalesced packets (LRO/RSC)    | Y   | Y      | Y      |
| `err_pkts_rcvd`      | RX error packets                  | Y   | Y      | Y      |
| `drop_pkts_dma`      | RX DMA drops                      | Y   | Y      | Y      |
| `good_pkts_txd`      | TX good packets (uni+multi+bcast) | Y   | Y      | Y      |
| `ucast_pkts_txd`     | TX unicast packets                | Y   | Y      | Y      |
| `mcast_pkts_txd`     | TX multicast packets              | Y   | Y      | Y      |
| `bcast_pkts_txd`     | TX broadcast packets              | Y   | Y      | Y      |
| `pause_frames_txd`   | TX Ethernet pause frames          | N   | N      | Y      |
| `err_pkts_txd`       | TX error packets                  | Y   | Y      | Y      |
| `good_octets_rcvd`   | RX good octets                    | Y   | Y      | Y      |
| `ucast_octets_rcvd`  | RX unicast octets                 | Y   | Y      | N      |
| `mcast_octets_rcvd`  | RX multicast octets               | Y   | Y      | N      |
| `bcast_octets_rcvd`  | RX broadcast octets               | Y   | Y      | N      |
| `good_octets_txd`    | TX good octets                    | Y   | Y      | Y      |
| `ucast_octets_txd`   | TX unicast octets                 | Y   | Y      | N      |
| `mcast_octets_txd`   | TX multicast octets               | Y   | Y      | N      |
| `bcast_octets_txd`   | TX broadcast octets               | Y   | Y      | N      |

Notes:
- On AQ1 and AQ2 `A0`, pause frame counters are not available.
- On AQ2 `B0`, per-cast octet counters are not available; use
  `good_octets_rcvd` / `good_octets_txd`.

### Per-queue Statistics

- `dev.aq.N.tx_queueM.*`: `tx_pkts`, `tx_bytes`, `tx_drops`,
  `tx_queue_full`, `tx_head`, `tx_tail`
- `dev.aq.N.rx_queueM.*`: `rx_pkts`, `rx_bytes`, `jumbo_pkts`, `rx_err`,
  `irq`, `rx_head`, `rx_tail`
