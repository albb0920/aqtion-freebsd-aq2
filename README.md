# FreeBSD driver

Atlantic driver for FreeBSD

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

## FW2x controls

These are only available on FW2x devices:

```
sysctl dev.aq.0.downshift=3
sysctl dev.aq.0.media_detect=1
sysctl dev.aq.0.loopback=1   # 0=off,1=int,2=ext
```
