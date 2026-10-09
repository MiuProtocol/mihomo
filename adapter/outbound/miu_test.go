package outbound

import (
	"testing"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
)

// Raw segments reach into the TLS connections of metacubex/tls and metacubex/utls. If this fails after
// one of them has been upgraded, Miu still works, but without raw segments.
func TestMiuRawSegmentsUsable(t *testing.T) {
	if !miuRawUsable() {
		t.Fatal("the Miu self-test failed: raw segments would be disabled")
	}
}

func TestMiuOption(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	parse := func(mapping map[string]any) (*Miu, error) {
		option := &MiuOption{}
		if err := decoder.Decode(mapping, option); err != nil {
			return nil, err
		}
		return NewMiu(*option)
	}
	base := func() map[string]any {
		return map[string]any{"name": "n", "type": "miu", "server": "example.com", "port": 443, "psk": "0123456789abcdef0123456789abcdef", "udp": true, "tls": true}
	}

	m, err := parse(base())
	if err != nil {
		t.Fatal(err)
	}
	if m.Type() != C.Miu || m.Type().String() != "Miu" || !m.SupportUDP() || m.Addr() != "example.com:443" || m.tlsConfig.Host != "example.com" {
		t.Fatalf("type %v, udp %v, addr %s, sni %s", m.Type(), m.SupportUDP(), m.Addr(), m.tlsConfig.Host)
	}
	_ = m.Close()

	for _, key := range []string{"sni", "servername"} {
		mapping := base()
		mapping[key] = "www.example.com"
		m, err := parse(mapping)
		if err != nil || m.tlsConfig.Host != "www.example.com" {
			t.Fatalf("%s: %v", key, err)
		}
		_ = m.Close()
	}

	reality := base()
	reality["reality-opts"] = map[string]any{"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short-id": "0123456789abcdef"}
	if _, err := parse(reality); err == nil {
		t.Fatal("reality-opts without client-fingerprint was accepted")
	}
	reality["client-fingerprint"] = "chrome"
	m, err = parse(reality)
	if err != nil || m.tlsConfig.Reality == nil {
		t.Fatalf("reality: %v", err)
	}
	_ = m.Close()

	short := base()
	short["psk"] = "short"
	if _, err := parse(short); err == nil {
		t.Fatal("a psk shorter than 16 characters was accepted")
	}
	missing := base()
	delete(missing, "psk")
	if _, err := parse(missing); err == nil {
		t.Fatal("a proxy without psk was accepted")
	}
}
