package main

import (
	"strings"
	"testing"
)

func TestSentinelConfigValidation(t *testing.T) {
	_, err := loadConfig(strings.NewReader(`{"version":1,"spop_listen":":0","redis":{"sentinel":{"addrs":["127.0.0.1:26379"]}}}`))
	if err == nil {
		t.Fatal("expected sentinel master_name error")
	}
	_, err = loadConfig(strings.NewReader(`{"version":1,"spop_listen":":0","redis":{"sentinel":{"master_name":"mymaster","addrs":["127.0.0.1:26379"]}},"admission_ttl_seconds":120}`))
	if err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidation(t *testing.T) {
	_, err := loadConfig(strings.NewReader(`{"version":1,"spop_listen":":0","redis":{"addr":"127.0.0.1:6379"},"admission_ttl_seconds":5}`))
	if err == nil {
		t.Fatal("expected admission ttl error")
	}
	_, err = loadConfig(strings.NewReader(`{"version":1,"spop_listen":":0","redis":{"addr":"127.0.0.1:6379"},"admin_read_socket":"/tmp/x","admin_write_socket":"/tmp/x"}`))
	if err == nil {
		t.Fatal("expected socket collision")
	}
}

