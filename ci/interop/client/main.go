package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"
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

// goclient <addr> <group> <ca.pem>
func main() {
	addr, want, caPath := os.Args[1], os.Args[2], os.Args[3]

	cid, ok := groupByName(want)
	if !ok {
		fmt.Printf("RESULT=FAIL reason=go-does-not-support-group group=%s\n", want)
		os.Exit(2)
	}

	pem, err := os.ReadFile(caPath)
	if err != nil {
		fmt.Printf("RESULT=FAIL reason=read-ca err=%v\n", err)
		os.Exit(2)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		fmt.Printf("RESULT=FAIL reason=bad-ca\n")
		os.Exit(2)
	}

	// Offer only the group under test.
	cfg := &tls.Config{
		RootCAs:          pool,
		ServerName:       "localhost",
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{cid},
	}

	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		fmt.Printf("RESULT=FAIL group=%s err=%v\n", want, err)
		os.Exit(1)
	}
	defer conn.Close()

	st := conn.ConnectionState()
	fmt.Printf("RESULT=PASS group=%s negotiated=%v version=%s cipher=%s\n",
		want, st.CurveID, tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite))

	// The peer may be `openssl s_server -www` or the Go server. Send an HTTP
	// request with a bounded read; the result is decided by the handshake.
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		first, _, _ := strings.Cut(string(buf[:n]), "\n")
		fmt.Printf("APPDATA_RX=%q\n", strings.TrimSpace(first))
	}
}
