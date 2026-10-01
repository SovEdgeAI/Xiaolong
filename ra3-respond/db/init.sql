-- =====================================================================
-- RA3 Threat Response System — database initialization
-- Creates the 3 core tables and seeds the static action catalog.
-- Executed automatically by the postgres container on first boot.
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- for gen_random_uuid()

-- ---------------------------------------------------------------------
-- Table 1: actions — static catalog of response measures
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS actions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(100) UNIQUE NOT NULL,
    display_name        VARCHAR(200) NOT NULL,
    description         TEXT NOT NULL,
    applicable_threats  TEXT[] NOT NULL DEFAULT '{}',
    parameters_schema   JSONB NOT NULL DEFAULT '{}'::jsonb,
    severity_threshold  VARCHAR(20) NOT NULL DEFAULT 'low',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- Table 2: incidents — reported threat events
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id    VARCHAR(100) NOT NULL,
    attack_type  VARCHAR(100) NOT NULL,
    severity     VARCHAR(20) NOT NULL,
    confidence   FLOAT NOT NULL,
    metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
    status       VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_incidents_attack_type ON incidents (attack_type);
CREATE INDEX IF NOT EXISTS ix_incidents_severity    ON incidents (severity);
CREATE INDEX IF NOT EXISTS ix_incidents_status      ON incidents (status);
CREATE INDEX IF NOT EXISTS ix_incidents_created_at  ON incidents (created_at DESC);

-- ---------------------------------------------------------------------
-- Table 3: responses — LLM decision results
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS responses (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id       UUID NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    selected_actions  JSONB NOT NULL DEFAULT '[]'::jsonb,
    execution_results JSONB NOT NULL DEFAULT '[]'::jsonb,
    llm_reasoning     TEXT,
    raw_llm_response  JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_responses_incident_id ON responses (incident_id);

-- ---------------------------------------------------------------------
-- Table 4: training_jobs — fine-tuning jobs for the local decision model
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS training_jobs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status      VARCHAR(20) NOT NULL DEFAULT 'queued',
    trigger     VARCHAR(50) NOT NULL,
    mode        VARCHAR(20) NOT NULL,
    spec        JSONB NOT NULL DEFAULT '{}'::jsonb,
    result      JSONB,
    error       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_training_jobs_status     ON training_jobs (status);
CREATE INDEX IF NOT EXISTS ix_training_jobs_created_at ON training_jobs (created_at DESC);

-- ---------------------------------------------------------------------
-- Seed data: the 9 predefined response actions
-- parameters_schema mirrors the JSON-Schema `input_schema` used for
-- Claude function calling (see server/actions.py).
-- ---------------------------------------------------------------------
INSERT INTO actions (name, display_name, description, applicable_threats, parameters_schema, severity_threshold)
VALUES
(
    'enable_syn_cookie',
    'Enable SYN Cookie',
    'Enable SYN Cookie on the target node to stop half-open TCP connections from exhausting the connection state table.',
    ARRAY['SYN_Flood'],
    '{"type":"object","properties":{"client_id":{"type":"string","description":"Target node ID, e.g. bs_node_01"},"duration_minutes":{"type":"integer","description":"How long to keep SYN cookies enabled","default":60}},"required":["client_id"]}'::jsonb,
    'medium'
),
(
    'rate_limit',
    'Protocol Rate Limit',
    'Apply an inbound packet-rate limit for a given protocol to blunt volumetric floods.',
    ARRAY['ICMP_Flood','UDP_Flood'],
    '{"type":"object","properties":{"client_id":{"type":"string","description":"Target node ID"},"protocol":{"type":"string","enum":["icmp","udp","tcp"],"description":"Protocol to rate limit"},"pps_limit":{"type":"integer","description":"Max packets per second allowed"}},"required":["client_id","protocol","pps_limit"]}'::jsonb,
    'medium'
),
(
    'block_ip',
    'Block Source IPs',
    'Block a batch of source IP addresses; entries are automatically released after duration_minutes.',
    ARRAY['HTTP_Flood','SYN_Scan','TCP_Connect_Scan','UDP_Scan'],
    '{"type":"object","properties":{"client_id":{"type":"string","description":"Target node ID"},"ip_list":{"type":"array","items":{"type":"string"},"description":"Source IPs to block"},"duration_minutes":{"type":"integer","description":"Auto-unblock after this many minutes","default":30}},"required":["client_id","ip_list"]}'::jsonb,
    'medium'
),
(
    'set_connection_timeout',
    'Shorten Connection Timeout',
    'Shorten the connection idle timeout to evict slow-rate connections that hold resources hostage.',
    ARRAY['Slowrate_DoS'],
    '{"type":"object","properties":{"client_id":{"type":"string","description":"Target node ID"},"timeout_seconds":{"type":"integer","description":"New connection idle timeout in seconds"}},"required":["client_id","timeout_seconds"]}'::jsonb,
    'medium'
),
(
    'close_unnecessary_ports',
    'Close Unnecessary Ports',
    'Close unnecessary open ports to reduce the attack surface exposed to scanners.',
    ARRAY['SYN_Scan','TCP_Connect_Scan','UDP_Scan'],
    '{"type":"object","properties":{"client_id":{"type":"string","description":"Target node ID"},"port_list":{"type":"array","items":{"type":"integer"},"description":"Ports to close"}},"required":["client_id","port_list"]}'::jsonb,
    'low'
),
(
    'enable_http_rate_limit',
    'HTTP Rate Limit',
    'Rate limit HTTP requests at the WAF / reverse-proxy layer to absorb application-layer floods.',
    ARRAY['HTTP_Flood'],
    '{"type":"object","properties":{"client_id":{"type":"string","description":"Target node ID"},"requests_per_minute":{"type":"integer","description":"Allowed requests per minute"},"per_ip":{"type":"boolean","description":"Apply the limit per source IP","default":true}},"required":["client_id","requests_per_minute"]}'::jsonb,
    'medium'
),
(
    'throttle_ue_bandwidth',
    'Throttle UE Bandwidth',
    '5G-native graduated mitigation: cap the offending UE''s bandwidth (QoS/AMBR) instead of cutting it off, enforced as a per-UE rate meter at the switch plus the subscriber AMBR in the core.',
    ARRAY['ICMP_Flood','UDP_Flood','SYN_Flood','HTTP_Flood'],
    '{"type":"object","properties":{"client_id":{"type":"string","description":"Target UE / node ID"},"mbps":{"type":"integer","description":"Downlink/uplink cap to apply to the UE, in Mbit/s","default":5},"duration_minutes":{"type":"integer","description":"Auto-restore the UE bandwidth after this many minutes","default":30}},"required":["client_id"]}'::jsonb,
    'medium'
),
(
    'quarantine_ue',
    'Quarantine UE',
    '5G-native cut-off: isolate the offending UE at the switch AND bar the subscriber in the 5G core so it cannot re-register. More surgical than block_ip (targets the subscriber, not an IP).',
    ARRAY['ICMP_Flood','UDP_Flood','SYN_Flood','HTTP_Flood','Slowrate_DoS','SYN_Scan','TCP_Connect_Scan','UDP_Scan'],
    '{"type":"object","properties":{"client_id":{"type":"string","description":"Target UE / node ID"},"duration_minutes":{"type":"integer","description":"Auto-release the quarantine after this many minutes","default":30},"reason":{"type":"string","description":"Why the UE is quarantined","default":""}},"required":["client_id"]}'::jsonb,
    'high'
),
(
    'alert_operator',
    'Alert Operator',
    'Notify on-call operations staff. MANDATORY when severity is high or critical.',
    ARRAY['ICMP_Flood','UDP_Flood','SYN_Flood','HTTP_Flood','Slowrate_DoS','SYN_Scan','TCP_Connect_Scan','UDP_Scan'],
    '{"type":"object","properties":{"incident_id":{"type":"string","description":"The incident this alert refers to"},"severity":{"type":"string","enum":["low","medium","high","critical"],"description":"Severity to report"},"message":{"type":"string","description":"Human-readable alert message"},"channel":{"type":"string","enum":["email","sms","slack","pagerduty"],"description":"Notification channel","default":"email"}},"required":["incident_id","severity","message"]}'::jsonb,
    'high'
),
(
    'log_incident',
    'Log Incident',
    'Write a complete audit log entry for the incident. MANDATORY on every response for traceability.',
    ARRAY['ICMP_Flood','UDP_Flood','SYN_Flood','HTTP_Flood','Slowrate_DoS','SYN_Scan','TCP_Connect_Scan','UDP_Scan'],
    '{"type":"object","properties":{"incident_id":{"type":"string","description":"The incident being logged"},"action_taken":{"type":"string","description":"Summary of the actions taken"},"notes":{"type":"string","description":"Optional additional notes","default":""}},"required":["incident_id","action_taken"]}'::jsonb,
    'low'
),
(
    'share_threat_intel',
    'Share Threat Intelligence',
    'Broadcast threat intelligence to peer nodes to trigger a federated early-warning. Use when multiple nodes report the same threat.',
    ARRAY['ICMP_Flood','UDP_Flood','SYN_Flood','HTTP_Flood','Slowrate_DoS','SYN_Scan','TCP_Connect_Scan','UDP_Scan'],
    '{"type":"object","properties":{"attack_type":{"type":"string","description":"The threat class being shared"},"source_pattern":{"type":"string","description":"Observed source pattern / signature"},"affected_nodes":{"type":"array","items":{"type":"string"},"description":"Nodes known to be affected"}},"required":["attack_type","source_pattern","affected_nodes"]}'::jsonb,
    'low'
)
ON CONFLICT (name) DO NOTHING;
