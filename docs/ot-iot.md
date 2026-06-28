# OT/IoT Protocol Support

CNSL can ingest logs from Operational Technology (OT) and Industrial
Control System (ICS) environments and apply the same detection pipeline
used for IT logs -- kill chain tracking, zero-trust scoring, pattern
learning, and SIEM forwarding.

This closes the OT/ICS gap from the original CNSL research paper:

> "Future work includes OT/ICS protocol support: Modbus, DNP3, and
>  generic SCADA log ingestion for industrial environments."


## Supported protocols

| Protocol | Scope | Typical devices |
|:---|:---|:---|
| Modbus TCP/RTU | Read sweep detection, write command alerting, exception codes | PLCs, VFDs, energy meters, HVAC controllers |
| DNP3 | Unsolicited response detection, Secure Authentication failures | Power substations, RTUs, field devices |
| SCADA/HMI | Alarm flood detection, unauthorized command attempts | Wonderware, Ignition, Kepware, FactoryTalk |

> These parsers read log file lines from OT gateways. They do NOT do
> packet-level protocol parsing. For deep Modbus/DNP3 packet analysis,
> use Zeek with the Zeek-ICS plugin and feed the resulting logs through
> CNSL's Zeek parser (`docs/zeek.md`).


## Why OT logs need different treatment

OT logs are sparse. A correctly functioning PLC may log nothing for
days. This means anomalies are more meaningful here than in IT:

- Any write command to a PLC from an unexpected IP is immediately
  suspicious -- legitimate SCADA systems use a fixed set of known IPs
- Repeated function-code read sweeps = reconnaissance of PLC register layout
- DNP3 unsolicited responses from unknown IPs = possible C2 or manipulation
- SCADA alarm flooding = possible denial-of-service or process disruption


## Event kinds

| Kind | Protocol | What it means |
|:---|:---|:---|
| `OT_MODBUS_SCAN` | Modbus | FC 1-4 read sweep from non-trusted IP |
| `OT_MODBUS_WRITE` | Modbus | FC 5/6/15/16 write from any IP |
| `OT_MODBUS_EXCEPTION` | Modbus | Device returned exception code (error or attack response) |
| `OT_DNP3_UNSOLICITED` | DNP3 | Unsolicited response from non-trusted source |
| `OT_DNP3_AUTH_FAIL` | DNP3 | DNP3 Secure Authentication failure |
| `OT_SCADA_ALARM` | SCADA | HMI/SCADA alarm message |
| `OT_UNAUTHORIZED_CMD` | SCADA | Explicit "unauthorized" or "denied" in OT log |


## Detection rules

| Rule ID | Severity | Threshold | Window | Trigger |
|:---|:---|:---|:---|:---|
| `ot.modbus_write` | HIGH | 1 | -- | Any Modbus write FC (5/6/15/16) from any IP |
| `ot.modbus_scan` | MEDIUM | 5 | 60s | Repeated Modbus read sweeps from one IP |
| `ot.scada_alarm` | HIGH | 1 | -- | SCADA alarm, DNP3 auth fail, or unauthorized command |

`ot.modbus_write` fires on the first write regardless of the source IP
-- even trusted IPs. Writes to PLCs are rarely legitimate from anything
other than the SCADA master, and that should be reflected in the
`trusted_ips` list rather than disabling the rule.


## Kill chain integration

OT events map to kill chain stages:

| OT event kind | Kill chain stage |
|:---|:---|
| `OT_MODBUS_SCAN` | Reconnaissance (stage 0) |
| `OT_DNP3_UNSOLICITED` | Delivery (stage 2) |
| `OT_MODBUS_WRITE` | Exploitation (stage 3) |
| `OT_SCADA_ALARM` | Actions on Objectives (stage 6) |
| `OT_UNAUTHORIZED_CMD` | Exploitation (stage 3) |
| `OT_DNP3_AUTH_FAIL` | Delivery (stage 2) |

This means an attacker who scans Modbus registers (Reconnaissance),
then issues a write command (Exploitation), will have both stages
visible in a single kill chain -- even if the events come minutes apart.


## Configuration

```json
{
  "ot": {
    "enabled": true,
    "log_sources": {
      "modbus": "/var/log/modbus-gateway.log",
      "dnp3":   "/var/log/dnp3-gateway.log",
      "scada":  "/var/log/scada-hmi.log"
    },
    "trusted_ips":        ["192.168.100.10", "192.168.100.11"],
    "alert_on_any_write": true
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `false` | Enable OT log ingestion |
| `log_sources.modbus` | `""` | Path to Modbus gateway log file |
| `log_sources.dnp3` | `""` | Path to DNP3 gateway log file |
| `log_sources.scada` | `""` | Path to SCADA/HMI syslog file |
| `trusted_ips` | `[]` | IPs that are allowed to read from PLCs without triggering `OT_MODBUS_SCAN`. Writes are always alerted regardless. |
| `alert_on_any_write` | `true` | Fire `OT_MODBUS_WRITE` on any write FC, even from trusted IPs |

### trusted_ips

Add your SCADA master station and engineering workstation IPs here.
Read commands (FC 1-4) from these IPs will not trigger `OT_MODBUS_SCAN`.
Write commands will still be alerted regardless of `trusted_ips` --
this is by design. If you want to suppress write alerts from a specific
IP, disable the `ot.modbus_write` rule via the dashboard Rules tab.


## Log format compatibility

CNSL's OT parsers use regex-based pattern matching and are compatible
with log lines from these common OT software stacks:

**Modbus:**
- mbpoll (open-source Modbus poller)
- libmodbus gateway logs
- EasyModbus server logs
- Prosoft Technology gateway syslog
- Moxa NPort / MGate syslog

**DNP3:**
- OpenDNP3 library log output
- Triangle MicroWorks SCADA Data Gateway syslog
- SEL RTAC syslog (DNP3 Secure Authentication events)

**SCADA/HMI:**
- Inductive Automation Ignition (audit log)
- AVEVA Wonderware (alarm journal export to syslog)
- Kepware KEPServerEX (event log forwarded via syslog)
- Rockwell FactoryTalk (historian alarm export)

If your OT system does not match these patterns, forward its logs to
CNSL via the remote syslog receiver (`docs/installation.md`) and file
a feature request for the specific log format.


## Setting up log forwarding from OT gateways

Most OT gateways support syslog forwarding. Configure them to send to
CNSL's syslog receiver (default port 5514):

**Linux-based OT gateway (rsyslog):**
```bash
echo "local0.* @CNSL_IP:5514" >> /etc/rsyslog.conf
systemctl restart rsyslog
```

**Cisco IOS / IOS-XE (for network-adjacent OT):**
```
logging host CNSL_IP transport udp port 5514
logging facility local0
```

Then point `ot.log_sources.scada` at the syslog file that receives
these forwarded messages, or use the syslog receiver directly (events
will be parsed and routed through the standard detection pipeline).


## REST API

OT events appear in the standard incident and event APIs:

```
GET /api/incidents?severity=HIGH     -- includes OT incidents
GET /api/incidents?src_ip=192.168.100.99
GET /api/search?q=OT_MODBUS_WRITE
GET /api/kill-chain/192.168.100.99   -- kill chain for OT attacker IP
```

OT rules are managed through the standard rules API:

```
GET  /api/rules/ot.modbus_write
PATCH /api/rules/ot.modbus_scan      -- adjust threshold or disable
POST /api/rules/ot.scada_alarm/disable
```


## Origin

OT/ICS protocol support was listed as future work in the original CNSL
research paper. The paper noted that critical infrastructure environments
needed the same correlation and kill-chain tracking capabilities as IT
environments, but that OT log formats required dedicated parsers.

The original research papers are available in the separate
`cnsl-research` repository.