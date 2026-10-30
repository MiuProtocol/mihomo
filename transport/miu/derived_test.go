package miu

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
)

// testdata/miu-padding-profile-v1.json holds the reference vectors of the derived padding profile:
// every implementation has to produce exactly these scheme texts, since the md5 of the text is what
// client and server compare.
type derivedVectors struct {
	Vectors []struct {
		ID     string `json:"id"`
		PSK    string `json:"psk"`
		Token  string `json:"auth_token_sha256_hex"`
		Scheme struct {
			Text string `json:"text"`
			MD5  string `json:"md5"`
		} `json:"scheme"`
	} `json:"vectors"`
}

func loadDerivedVectors(t *testing.T) derivedVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/miu-padding-profile-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v derivedVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) < 2 {
		t.Fatal("not enough vectors")
	}
	return v
}

func TestDerivedSchemeVectors(t *testing.T) {
	for _, v := range loadDerivedVectors(t).Vectors {
		token, err := pskToken(v.PSK)
		if err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
		if got := hex.EncodeToString(token[:]); got != v.Token {
			t.Fatalf("%s: token %s, want %s", v.ID, got, v.Token)
		}
		p, err := derivePaddingScheme(token)
		if err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
		if string(p.raw) != v.Scheme.Text {
			t.Fatalf("%s: scheme\n%s\nwant\n%s", v.ID, p.raw, v.Scheme.Text)
		}
		if got := fmt.Sprintf("%x", md5.Sum(p.raw)); got != v.Scheme.MD5 || p.md5 != v.Scheme.MD5 {
			t.Fatalf("%s: md5 %s / %s, want %s", v.ID, got, p.md5, v.Scheme.MD5)
		}
	}
}

// A profile never needs more than the first 128 bytes, so the vectors do not reach the following
// HKDF blocks; check them on the reader itself. The values come from an independent implementation
// of the same rules.
func TestDerivedReaderBlocks(t *testing.T) {
	r, err := newDerivedPaddingReader(sha256.Sum256([]byte("diff-psk-7")))
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]uint16{0: 10632, 63: 11859, 64: 4367, 127: 45120, 128: 18335, 192: 45282, 299: 23894}
	for i := 0; i < 300; i++ {
		x, err := r.uint16()
		if err != nil {
			t.Fatal(err)
		}
		if w, ok := want[i]; ok && x != w {
			t.Fatalf("value %d: %d, want %d", i, x, w)
		}
	}
	if r.counter != 4 {
		t.Fatalf("counter %d after 300 values, want 4", r.counter)
	}
}

// Derived schemes stay within the bounds the rest of the protocol relies on.
func TestDerivedSchemeBounds(t *testing.T) {
	for i := 0; i < 2000; i++ {
		p, err := derivePaddingScheme(sha256.Sum256([]byte(fmt.Sprintf("bounds-psk-%04d", i))))
		if err != nil {
			t.Fatal(err)
		}
		if p.stop < 5 || p.stop > 10 {
			t.Fatalf("stop %d: %q", p.stop, p.raw)
		}
		total := 0
		for pkt := uint32(0); pkt < p.stop; pkt++ {
			sizes := p.sizesFor(pkt)
			if len(sizes) == 0 {
				t.Fatalf("packet %d has no sizes: %q", pkt, p.raw)
			}
			for _, s := range sizes {
				if s == checkMark {
					continue
				}
				if pkt > 0 && (s < 128 || s >= 8192) {
					t.Fatalf("record size %d: %q", s, p.raw)
				}
				total += s
			}
		}
		if total > derivedProfileBudget {
			t.Fatalf("over budget %d: %q", total, p.raw)
		}
	}
}

func noDial(context.Context) (net.Conn, error) { return nil, io.ErrClosedPipe }

// A new client starts from the scheme derived from its PSK; a configured scheme wins; a broken one
// is refused.
func TestClientInitialScheme(t *testing.T) {
	vs := loadDerivedVectors(t).Vectors
	c, err := NewClient(ClientConfig{PSK: "  " + vs[0].PSK + "\n", Dial: noDial})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.scheme.Load(); string(got.raw) != vs[0].Scheme.Text {
		t.Fatalf("initial scheme %q", got.raw)
	}
	other, err := NewClient(ClientConfig{PSK: vs[1].PSK, Dial: noDial})
	if err != nil {
		t.Fatal(err)
	}
	if other.scheme.Load().md5 != vs[1].Scheme.MD5 {
		t.Fatalf("second PSK: %q", other.scheme.Load().raw)
	}

	const explicit = "stop=2\n0=30-30\n1=128-160"
	c, err = NewClient(ClientConfig{PSK: vs[0].PSK, Dial: noDial, PaddingScheme: explicit})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.scheme.Load(); string(got.raw) != explicit {
		t.Fatalf("configured scheme not used: %q", got.raw)
	}
	if _, err := NewClient(ClientConfig{PSK: vs[0].PSK, Dial: noDial, PaddingScheme: "not-a-scheme"}); err == nil {
		t.Fatal("broken padding scheme accepted")
	}
}

// An UpdatePaddingScheme from the server is remembered by the client: the lanes dialed after it
// start from that scheme (its md5 in Settings, its item 0 as the authentication padding).
func TestClientRemembersUpdatedScheme(t *testing.T) {
	v := loadDerivedVectors(t).Vectors[0]
	ends := make(chan net.Conn, 1)
	c, err := NewClient(ClientConfig{PSK: v.PSK, Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		ends <- b
		return a, nil
	}})
	if err != nil {
		t.Fatal(err)
	}

	first, _ := net.Pipe()
	l := newLane(first, false, false)
	l.client = c // as dial does
	l.scheme.Store(c.scheme.Load())
	if err := l.control(frUpdatePadding, []byte("not-a-scheme")); err != nil {
		t.Fatal(err)
	}
	if c.scheme.Load().md5 != v.Scheme.MD5 || l.scheme.Load().md5 != v.Scheme.MD5 {
		t.Fatal("a broken update replaced the scheme")
	}
	const update = "stop=2\n0=7-7\n1=128-160"
	if err := l.control(frUpdatePadding, []byte(update)); err != nil {
		t.Fatal(err)
	}
	if string(l.scheme.Load().raw) != update || string(c.scheme.Load().raw) != update {
		t.Fatalf("update not taken: lane %q, client %q", l.scheme.Load().raw, c.scheme.Load().raw)
	}
	l.close()

	type hello struct {
		padlen int
		md5    string
		err    error
	}
	got := make(chan hello, 1)
	go func() {
		var h hello
		defer func() { got <- h }()
		serverEnd := <-ends
		defer serverEnd.Close()
		head := make([]byte, authHead)
		if _, h.err = io.ReadFull(serverEnd, head); h.err != nil {
			return
		}
		h.padlen = int(binary.BigEndian.Uint16(head[32:]))
		if _, h.err = io.ReadFull(serverEnd, make([]byte, h.padlen)); h.err != nil {
			return
		}
		fh := make([]byte, frameHead)
		if _, h.err = io.ReadFull(serverEnd, fh); h.err != nil {
			return
		}
		if fh[0] != frSettings {
			h.err = fmt.Errorf("frame %d, want Settings", fh[0])
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(fh[1:]))
		if _, h.err = io.ReadFull(serverEnd, body); h.err != nil {
			return
		}
		h.md5 = parseKV(string(body))["padding-md5"]
	}()
	next, err := c.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer next.close()
	h := <-got
	if h.err != nil {
		t.Fatal(h.err)
	}
	want := parsePaddingScheme(update)
	if h.md5 != want.md5 || h.padlen != 7 {
		t.Fatalf("next lane: padding-md5 %s padlen %d, want %s and 7", h.md5, h.padlen, want.md5)
	}
}
