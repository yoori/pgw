#!/bin/bash

clickhouse-client --multiquery <<EOF

CREATE DATABASE gateway;

CREATE USER gatewayuser IDENTIFIED WITH plaintext_password BY 'gateway' DEFAULT DATABASE gateway;

CREATE TABLE gateway.detailed_traffic_stats (timestamp DateTime, msisdn String, traffic_type String, traffic_category String, source_ip String, destination_ip String, direction String, packets Int64, bytes Int64, shaped_packets Int64, shaped_bytes Int64, dropped_packets Int64, dropped_bytes Int64) ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (timestamp, msisdn, traffic_type, traffic_category, source_ip, destination_ip, direction) SETTINGS index_granularity=8192;

CREATE TABLE gateway.detailed_event_stats (timestamp DateTime, msisdn String, event String, count Int64) ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (timestamp, msisdn, event) SETTINGS index_granularity=8192;

GRANT SELECT,INSERT ON gateway.* TO gatewayuser;

EOF
