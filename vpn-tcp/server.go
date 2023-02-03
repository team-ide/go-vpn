package vpn_tcp

import (
	"crypto/tls"
	"github.com/golang/snappy"
	"net"
	"time"
)

func ServerStart(config *Config) (err error) {
	var tlsConfig *tls.Config = nil
	if config.CertificateFilePath != "" {
		var cert tls.Certificate
		cert, err = tls.LoadX509KeyPair(config.CertificateFilePath, config.CertificateKeyFilePath)
		if err != nil {
			return
		}
		tlsConfig = &tls.Config{
			Certificates:     []tls.Certificate{cert},
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			},
		}
	}

	var listener net.Listener
	if tlsConfig != nil {
		listener, err = tls.Listen("tcp", config.Address, tlsConfig)
	} else {
		listener, err = net.Listen("tcp", config.Address)
	}
	if err != nil {
		return
	}

	for {
		conn, e := listener.Accept()
		if e != nil {
			continue
		}
		sniffConn := NewPeekPreDataConn(conn)
		switch sniffConn.Type {
		case TypeHttp:
			if sniffConn.Handle() {
				continue
			}
		case TypeHttp2:
			if sniffConn.Handle() {
				continue
			}
		}
		go toServer(config, sniffConn)
	}
	return
}

func toClient(config *Config) {
	packet := make([]byte, BufferSize)
	var n int
	var err error
	for {
		//n, err := iface.Read(packet)
		if err != nil {
			continue
		}
		b := packet[:n]
		if key := GetDstKey(b); key != "" {
			if v, ok := timeCache.Get(key); ok {
				if config.Compress {
					b = snappy.Encode(nil, b)
				}
				_, e := v.(net.Conn).Write(b)
				if e != nil {
					timeCache.Delete(key)
					continue
				}
			}
		}
	}
}

func toServer(config *Config, tcpConn net.Conn) {
	defer tcpConn.Close()
	packet := make([]byte, BufferSize)
	for {
		n, err := tcpConn.Read(packet)
		if err != nil {
			break
		}
		b := packet[:n]
		if config.Compress {
			b, err = snappy.Decode(nil, b)
			if err != nil {
				break
			}
		}
		if key := GetSrcKey(b); key != "" {
			timeCache.Set(key, tcpConn, 24*time.Hour)
			//iface.Write(b)
		}
	}
}
