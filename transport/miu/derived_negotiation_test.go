package miu

import (
	"context"
	"net"
	"testing"
	"time"
)

// Exercise real authentication and Settings frames, not just scheme setters: without a configured
// scheme the server uses the one derived from each user's PSK, and only sends UpdatePaddingScheme to a
// client whose md5 differs from it.
func TestDerivedServerNegotiation(t *testing.T) {
	const (
		pskA = "miu-test-psk-alpha-2026"
		pskB = "another-test-user-psk-2026"
	)
	for _, explicit := range []string{"", "stop=2\n0=40-40\n1=128-160"} {
		srv, err := NewServer(ServerConfig{Users: []User{{Name: "a", PSK: pskA}, {Name: "b", PSK: pskB}}, PaddingScheme: explicit})
		if err != nil {
			t.Fatal(err)
		}
		for _, psk := range []string{pskA, pskB} {
			token, err := pskToken(psk)
			if err != nil {
				t.Fatal(err)
			}
			expected := explicit
			if expected == "" {
				p, err := derivePaddingScheme(token)
				if err != nil {
					t.Fatal(err)
				}
				expected = string(p.raw)
			}
			for _, match := range []bool{false, true} {
				a, b := net.Pipe()
				a.SetDeadline(time.Now().Add(3 * time.Second))
				b.SetDeadline(time.Now().Add(3 * time.Second))
				done := make(chan error, 1)
				go func() { done <- srv.Serve(context.Background(), b) }()
				md5 := defaultScheme.md5
				if match {
					md5 = parsePaddingScheme(expected).md5
				}
				hello := append(append([]byte{}, token[:]...), 0, 0)
				hello = appendFrame(hello, frSettings, []byte("v=2\nraw=0\npadding-md5="+md5))
				if _, err = a.Write(hello); err != nil {
					t.Fatal(err)
				}
				l := newLane(a, false, false)
				typ, _, err := l.next()
				if err != nil || typ != frServerSettings {
					t.Fatalf("settings: %d %v", typ, err)
				}
				if !match {
					typ, p, err := l.next()
					if err != nil || typ != frUpdatePadding || string(p) != expected {
						t.Fatalf("user-specific update: type=%d err=%v payload=%q", typ, err, p)
					}
				} else {
					// A mismatched extra update would arrive instead of this read timing out.
					a.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
					_, _, err = l.next()
					if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
						t.Fatalf("unexpected matching-scheme response: %v", err)
					}
				}
				a.Close()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
