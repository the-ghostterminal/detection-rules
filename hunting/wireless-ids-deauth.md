# Wireless IDS: deauth floods and probe bursts

The two Sigma rules next to this note cover what happens **on the host that is
attacking**: somebody switched a radio to monitor mode and started a capture.
This note covers the other direction - what the wireless infrastructure sees
while it happens. There is no portable log format for 802.11 management frames,
so there is no CI-checked rule here; every WIDS writes its own schema.

## Why these two events

| Event | What it looks like | What it usually means |
|---|---|---|
| **Deauthentication / disassociation flood** | Many `deauth` frames, same BSSID, different client MACs, reason code **7** ("class 3 frame received from nonassociated station") or **2** | Forcing clients to re-associate so the next EAPOL handshake can be captured. The handshake itself is what gets cracked offline |
| **Probe request burst** | One station MAC emitting tens of probe requests per second across every SSID in range, often with locally-administered (randomised) MACs | Either a survey tool enumerating the area or a device with broken roaming. At high rate it is `probe`-based location tracking or a rogue AP hunt |

A single deauth is normal - every access point sends them on roam, on idle
timeout and on a channel change. The signal is **rate against a baseline**, not
the frame type.

## Detecting it

If your infrastructure is UniFi, Meraki or Cisco, the controller already raises
a "deauth flood" / "rogue AP" alert and this becomes a matter of forwarding that
alert into the SIEM instead of building a detector. Do not rebuild what the
vendor already does.

If there is no controller, capture management frames directly. Radiotap on a
monitor interface, no association required:

```bash
# management frames only, no beacons, 60 s sample
tcpdump -i wlan0mon -w mgmt.pcapng 'type mgt and not subtype beacon'
```

Then count per source per minute rather than reading frames by hand:

```bash
tshark -r mgmt.pcapng -Y 'wlan.fc.type_subtype == 0x000c' \
  -T fields -e wlan.sa -e wlan.bssid | sort | uniq -c | sort -rn | head
```

`0x000c` is a deauthentication frame. Thresholds that hold in a small office:
**more than 5 deauths per client per minute**, or **more than 20 to distinct
clients from one BSSID per minute**. Both are far above roam and idle behaviour
and far below what a cracking setup needs.

## As a custom logsource

If the WIDS log is already parsed into events with `event_type`, `src_mac` and a
`count`, the rule shape is:

```yaml
title: Wireless Deauthentication Flood
id: 9a1c4a2e-3f7b-4c19-9d55-1c6a2f0b7e41
status: experimental
logsource:
  product: wifi
  service: wids
detection:
  selection:
    event_type: deauth
  timeframe: 1m
  condition: selection | count(src_mac) by bssid > 20
level: medium
```

This is **not** in `rules/` on purpose: `product: wifi` is not a backend the CI
`sigma check` job can resolve, and shipping a rule nobody can convert is worse
than documenting the logic. The host-side rules beside it are the ones that are
portable.

## Limitations worth stating out loud

- **802.11w (PMF) changes the picture.** With management frame protection
  enforced, forged deauths are dropped and the flood produces a "PMF violation"
  instead. Alert on that separately - it is the same attacker, better disguised.
- **MAC randomisation breaks counting.** A client rotating its MAC per probe
  looks like many devices doing one probe each. Group by the information
  element fingerprint (`wlan.tag` order), not by MAC, or the burst is invisible.
- **Passive capture is local.** A monitor interface only sees its own channel;
  a 5 GHz attacker on channel 149 is invisible to a 2.4 GHz-only sensor. Coverage
  is a radio problem, not a detection-logic problem.
- **The WIDS box is a target.** It sits on the same spectrum and is usually
  unauthenticated. Treat its own logs as untrusted input.

## What a wireless intrusion looks like end to end

1. Monitor mode enabled on an attacker host - **`linux_wifi_monitor_mode_enabled`**.
2. Capture tool writes a pcapng - **`linux_wifi_capture_tool_writes_pcap`**.
3. Deauth flood toward the target AP to force a handshake - **this note**.
4. Handshake or PMKID cracked offline; the network sees nothing at this stage.
5. Re-association to the AP with recovered credentials - now it is an ordinary
   `802.1X` or `WPA-PSK` authentication event, and the wireless log looks normal.

Steps 1 and 2 are the ones that are cheap to detect and hard to explain away.
Step 3 is only visible with the right sensor placement. Steps 4 and 5 are where
wireless detection stops being sufficient and identity logs have to carry it.
