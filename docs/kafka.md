# Kafka Log Ingestion

CNSL can consume log events from Apache Kafka topics, enabling high-volume
log ingestion from multiple sources in a decoupled architecture.

## Architecture

```
Log Producers                  Kafka               CNSL
-------------                  -----               ----
nginx -> filebeat  ----------->  auth_logs  ------->  detection
auth.log -> logstash ----------> nginx_logs ------->  pipeline
app servers -> fluentd --------> syslog     ------->  alerts
zeek -> kafka producer --------> zeek_ssh   ------->  dashboard
```

CNSL supports two Kafka client libraries:
- **aiokafka** (preferred -- async, native Python)
- **confluent-kafka** (fallback -- C-based, higher throughput)

---

## Installation

```bash
# Preferred (async)
pip install aiokafka

# Alternative (higher throughput)
pip install confluent-kafka
```

---

## Config

```json
"kafka": {
  "enabled":           true,
  "bootstrap_servers": "kafka-1:9092,kafka-2:9092",
  "group_id":          "cnsl-consumer",
  "auto_offset_reset": "latest",
  "batch_size":        100,
  "poll_timeout_ms":   1000,
  "commit_interval":   5,
  "topics": {
    "auth_logs":   { "parser": "auth",      "enabled": true  },
    "nginx_logs":  { "parser": "nginx",     "enabled": true  },
    "apache_logs": { "parser": "apache",    "enabled": false },
    "mysql_logs":  { "parser": "mysql",     "enabled": false },
    "ufw_logs":    { "parser": "ufw",       "enabled": false },
    "syslog":      { "parser": "syslog",    "enabled": true  },
    "cnsl_events": { "parser": "json",      "enabled": true  },
    "zeek_ssh":    { "parser": "zeek_ssh",  "enabled": false },
    "zeek_http":   { "parser": "zeek_http", "enabled": false },
    "zeek_conn":   { "parser": "zeek_conn", "enabled": false }
  }
}
```

| Setting | Description |
|:---|:---|
| `bootstrap_servers` | Kafka broker(s), comma-separated |
| `group_id` | Consumer group ID (use unique ID per CNSL instance) |
| `auto_offset_reset` | `latest` (only new events) or `earliest` (replay) |
| `batch_size` | Max events per processing batch |
| `poll_timeout_ms` | Broker poll timeout in milliseconds |
| `commit_interval` | Commit offsets every N messages |

---

## Supported Parsers

| Parser key | Input format | Parses |
|:---|:---|:---|
| `auth` | Raw auth.log line | SSH fail/success |
| `nginx` | Combined access log line | Web events |
| `apache` | Combined access log line | Web events |
| `mysql` | MySQL error log line | DB auth failures |
| `ufw` | UFW log line | Firewall events |
| `syslog` | Syslog line | Sudo, cron, general |
| `json` | CNSL Event JSON | Any pre-parsed event |
| `zeek_ssh` | Zeek ssh.log JSON | SSH events |
| `zeek_http` | Zeek http.log JSON | Web events |
| `zeek_conn` | Zeek conn.log JSON | Connection events |
| `zeek_dns` | Zeek dns.log JSON | DNS events |
| `zeek_notice` | Zeek notice.log JSON | Zeek notices |
| `zeek_weird` | Zeek weird.log JSON | Protocol anomalies |

---

## Sending Events to Kafka

### From filebeat (auth.log -> Kafka)

```yaml
# /etc/filebeat/filebeat.yml
filebeat.inputs:
  - type: log
    paths: [/var/log/auth.log]
    tags: ["auth"]

output.kafka:
  hosts: ["kafka:9092"]
  topic: "auth_logs"
  codec.format:
    string: '%{[message]}'
```

### From logstash

```ruby
input { file { path => "/var/log/nginx/access.log" } }
output {
  kafka {
    bootstrap_servers => "kafka:9092"
    topic_id          => "nginx_logs"
    codec             => plain { format => "%{message}" }
  }
}
```

### JSON events directly

Send pre-serialised CNSL Event JSON to `cnsl_events` topic:

```json
{
  "kind":   "SSH_FAIL",
  "src_ip": "1.2.3.4",
  "source": "my-app",
  "ts":     1748685600.0,
  "user":   "admin",
  "meta":   {"port": 22}
}
```

---

## Dashboard API

```
GET /api/kafka
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/kafka
```

```json
{
  "enabled":           true,
  "topics":            ["auth_logs", "nginx_logs", "syslog"],
  "messages_received": 48293,
  "events_parsed":     47891,
  "parse_errors":      402
}
```

---

## High-Volume Tips

- Run multiple CNSL instances with the same `group_id` to distribute load
- Use `auto_offset_reset: latest` in production (don't replay old events)
- Set `batch_size: 500` for very high-volume topics
- Use `confluent-kafka` for >100k msg/sec (lower latency than aiokafka)
- Add a dead-letter topic for events that fail parsing