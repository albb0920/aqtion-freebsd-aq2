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

## Host Boot

Host boot loads NIC firmware from the host at boot time instead of relying
on the adapter flash. Use it when you want to try another firmware without
flashing the card, or when the card needs a host-provided image to boot.

Flash boot is the default. The driver only falls back to host boot
automatically when the adapter needs a host-provided image, such as a NIC
without flash ROM.

### 1. Install the firmware image

`hostboot_fw_image` is a FreeBSD firmware name as described in
`firmware(9)`, not an arbitrary path. When you leave it unset, the driver
picks a built-in name from the attached hardware:

- `aqc100x` -> `if_atlantic_fw_80B1`
- `aqc10xx` -> `if_atlantic_fw_87B1`
- `aqc11xx` -> `if_atlantic_fw_91B1`
- `aq2` -> `if_atlantic_fw_aq2`

AQ2 `.clx` images must be provisioned with the correct MAC/PHY blobs for your
board, otherwise host boot usually fails. You can do this with the
[aq2\_clx\_provision script](https://gitlab.com/-/snippets/5969424)

To package a firmware image, first create `Makefile`, with `KMOD` set to
the firmware name you want the driver to request. Using the built-in name
keeps `hostboot_fw_image` optional:

```make
KMOD= if_atlantic_fw_aq2
FIRMWS= your_blob.clx:if_atlantic_fw_aq2
.include <bsd.kmod.mk>
```

Run `make` then install `if_atlantic_fw_aq2.ko` in a directory from
`kern.module_path` (typically `/boot/modules`) or preload it before the
driver attaches.

If you pick a different firmware name, set `hostboot_fw_image` to that
name in the next section.

#### FreeBSD 15+ Shortcut

On FreeBSD 15 and later, you can skip the firmware KLD and install a raw
binary file under `/boot/firmware` using the same firmware name. AQ2 example:

```sh
install -m 644 AQC113-DirtyWake-Swap_Bx-1.5.38_bdp_aqsign.clx \
    /boot/firmware/if_atlantic_fw_aq2
```

If you want to keep the original filename, place it under
`/boot/firmware` and point `hostboot_fw_image` at that filename:

```sh
install -m 644 AQC113-Antigua_Bx-1.5.42_bdp_aqsign.clx \
    /boot/firmware/AQC113-Antigua_Bx-1.5.42_bdp_aqsign.clx
```

Then set `hostboot_fw_image="AQC113-Antigua_Bx-1.5.42_bdp_aqsign.clx"`
using one of the methods in the next section.

### 2. Forcing host boot

These are loader tunables. Set them in `/boot/loader.conf` for boot-time
use, or set them with `kenv(1)` before `kldload if_atlantic` if you are
loading the driver manually after boot.

Boot-time example in `/boot/loader.conf`:

```conf
hw.aq.hostboot_force=1
```

Add these only when you need them:

```conf
hw.aq.hostboot_fw_image="aq2testfw"
hw.aq.hostboot_provisioning_selector="00010000"
```

Runtime example before manually loading the module:

```sh
kenv hw.aq.hostboot_force=1
kenv hw.aq.hostboot_fw_image="aq2testfw"
kldload if_atlantic
```

`hostboot_fw_image` is only needed when you are not using the built-in
default name. Use the FreeBSD firmware name, not a path. For firmware
KLDs this is the name exported by `FIRMWS`.

On FreeBSD 15+ raw binary file, use the filename, or a relative path under
`/boot/firmware` if you stored the file in a subdirectory.

`hostboot_provisioning_selector` is only used with AQ1 hostboot images.

Use resource hints in `/boot/device.hints` to override one adapter at boot
time. Per-device hints take precedence over the global `hw.aq.*` values:

```conf
hint.aq.0.hostboot_force=1
hint.aq.0.hostboot_fw_image="if_atlantic_fw_87B1"
hint.aq.0.hostboot_provisioning_selector="12345678"
```

If the NIC attaches during early boot and you are using a firmware KLD,
preload the firmware module in `/boot/loader.conf`:

```conf
if_atlantic_fw_aq2_load="YES"
```

On FreeBSD 15+, if you are using a raw blob instead of a firmware KLD,
the loader can preload it directly:

```conf
aq2fw_load="YES"
aq2fw_name="/boot/firmware/if_atlantic_fw_aq2"
aq2fw_type="firmware"
```

### 3. Verify the result

Runtime status is exposed read-only under `dev.aq.N` sysctl:

```
sysctl dev.aq.0.hostboot_force
sysctl dev.aq.0.hostboot_fw_image
sysctl dev.aq.0.fw_ver
sysctl dev.aq.0.fw_iface_ver
```

Use `dev.aq.N.fw_ver` for the live firmware version reported by the driver.
`pciconf -lV` shows VPD strings stored on the adapter and can stay at the
flash version even when host boot loads a different bundle.

### AQ1 only: choose a provisioning record

AQ1 hostboot bundles can carry multiple provisioning records keyed by a
32-bit subsystem identifier. By default the driver uses:

```
(subdevice << 16) | subvendor
```

You can inspect those values with `pciconf -lv`, which prints fields such as
`subvendor=0x1d6a subdevice=0x0001`. The corresponding selector value is
`00011d6a`.

If your AQ1 bundle does not contain a record for your board, you can write
a specific selector value to `hostboot_provisioning_selector` to force a
different provisioning record, such as a generic one.

### Troubleshooting

On FreeBSD 14.0 through 15.0, kernel bug D54955 can still emit
`could not load binary firmware` warnings during the optional built-in
firmware probe even though the driver requests `FIRMWARE_GET_NOWARN`.
Those lines are harmless unless you expected that exact firmware name to
be present.

When using the raw-blob path on FreeBSD 15+, `firmware_get()` first tries
to autoload a same-named KLD. When no such module exists, the kernel logs
`imagename: could not load firmware image, error 8` and then falls back
to `/boot/firmware/<imagename>`. That line alone does not mean the raw
blob lookup failed.

If you loaded your firmware using a raw blob on FreeBSD 15+, FreeBSD
keeps it registered until reboot. If you want to replace the firmware,
reboot or choose a new image name.

If you preload a firmware KLD manually, the registered firmware name may be
different from the `.ko` filename. For on-demand automatic loading, use a
plain short name and keep the module filename and requested firmware name
aligned as shown above.

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
