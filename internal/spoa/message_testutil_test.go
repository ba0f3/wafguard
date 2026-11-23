package spoa

import (
	"testing"

	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
)

func mustMessage(t *testing.T, name string, kvs map[string]string) *encoding.Message {
	t.Helper()
	var header []byte
	varintBuf := make([]byte, 10)
	vn, err := encoding.PutVarint(varintBuf, uint64(len(name)))
	if err != nil {
		t.Fatal(err)
	}
	header = append(header, varintBuf[:vn]...)
	header = append(header, name...)
	header = append(header, byte(len(kvs)))

	buf := make([]byte, len(header)+8192)
	copy(buf, header)
	w := encoding.NewKVWriter(buf, len(header))
	for k, v := range kvs {
		if err := w.SetString(k, v); err != nil {
			t.Fatal(err)
		}
	}
	buf = buf[:w.Off()]
	ms := encoding.NewMessageScanner(buf)
	m := encoding.AcquireMessage()
	if !ms.Next(m) {
		if err := ms.Error(); err != nil {
			t.Fatal(err)
		}
		t.Fatal("no message")
	}
	return m
}

