package gosnmp

import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"
)

type QuicTransport struct {
	stream quic.Stream
	conn   quic.Connection
}

func ConnectQUIC(addr string, insecureMode bool) (*QuicTransport, error) {
	t := new(QuicTransport)
	tlsConf := &tls.Config{
		InsecureSkipVerify: insecureMode,
		NextProtos:         []string{"snmp-quic"},
	}

	conn, err := quic.DialAddr(context.Background(), addr, tlsConf, nil)
	if err != nil {
		return t, err
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return t, err
	}

	t.conn = conn
	t.stream = stream
	return t, nil
}

func (t *QuicTransport) Close() error {
	if t.stream != nil {
		t.stream.Close()
	}
	if t.conn != nil {
		return t.conn.CloseWithError(quic.ApplicationErrorCode(0), "")
	}
	return nil
}
