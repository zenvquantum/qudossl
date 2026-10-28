package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
)

func groupByName(n string) (tls.CurveID, bool) {
	switch n {
	case "X25519MLKEM768":
		return tls.X25519MLKEM768, true
	case "SecP256r1MLKEM768":
		return tls.SecP256r1MLKEM768, true
	case "SecP384r1MLKEM1024":
		return tls.SecP384r1MLKEM1024, true
	case "X25519":
		return tls.X25519, true
	}
	return 0, false
}

// goserver <addr> <groups-csv> <cert.pem> <key.pem>
func main() {
	addr, groups, certPath, keyPath := os.Args[1], os.Args[2], os.Args[3], os.Args[4]

	var cids []tls.CurveID
	for _, g := range strings.Split(groups, ",") {
		cid, ok := groupByName(g)
		if !ok {
			fmt.Printf("SERVER_FATAL unsupported-group=%s\n", g)
			os.Exit(2)
		}
		cids = append(cids, cid)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		fmt.Printf("SERVER_FATAL loadcert err=%v\n", err)
		os.Exit(2)
	}

	cfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: cids,
	}

	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		fmt.Printf("SERVER_FATAL listen err=%v\n", err)
		os.Exit(2)
	}
	fmt.Printf("SERVER_READY addr=%s groups=%s\n", addr, groups)
	os.Stdout.Sync()

	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			tc := c.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				fmt.Printf("SERVER_HANDSHAKE_FAIL err=%v\n", err)
				os.Stdout.Sync()
				return
			}
			st := tc.ConnectionState()
			fmt.Printf("SERVER_OK negotiated=%v version=%s cipher=%s\n",
				st.CurveID, tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite))
			os.Stdout.Sync()
			c.Write([]byte("hello-from-go-server\n"))
			buf := make([]byte, 256)
			n, _ := c.Read(buf)
			if n > 0 {
				fmt.Printf("SERVER_RX=%q\n", string(buf[:n]))
				os.Stdout.Sync()
			}
		}(c)
	}
}
