package outbound

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/once"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/mihomo/transport/miu"
	"github.com/metacubex/tls"
)

type Miu struct {
	*Base
	client    *miu.Client
	option    *MiuOption
	tlsConfig *vmess.TLSConfig
}

type MiuOption struct {
	BasicOption
	Name               string         `proxy:"name"`
	Server             string         `proxy:"server"`
	Port               int            `proxy:"port"`
	PSK                string         `proxy:"psk"`
	UDP                bool           `proxy:"udp,omitempty"`
	TLS                bool           `proxy:"tls,omitempty"` // accepted for compatibility: Miu always runs over TLS
	SNI                string         `proxy:"sni,omitempty"`
	ServerName         string         `proxy:"servername,omitempty"` // alias of sni
	ALPN               []string       `proxy:"alpn,omitempty"`
	SkipCertVerify     bool           `proxy:"skip-cert-verify,omitempty"`
	Fingerprint        string         `proxy:"fingerprint,omitempty"`
	ClientFingerprint  string         `proxy:"client-fingerprint,omitempty"`
	RealityOpts        RealityOptions `proxy:"reality-opts,omitempty"`
	IdleSessionTimeout int            `proxy:"idle-session-timeout,omitempty"`
	MinIdleSession     int            `proxy:"min-idle-session,omitempty"`
	PaddingScheme      []string       `proxy:"padding-scheme,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (m *Miu) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	// The destination goes to the server as it is: a domain name is resolved there.
	c, err := m.client.DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(c, m), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (m *Miu) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := m.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	// One UoT stream, on a lane of its own, opened by the first packet written.
	pc, err := m.client.ListenPacket()
	if err != nil {
		return nil, err
	}
	return NewPacketConn(pc, m), nil
}

// SupportUOT implements C.ProxyAdapter
func (m *Miu) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (m *Miu) ProxyInfo() C.ProxyInfo {
	info := m.Base.ProxyInfo()
	info.DialerProxy = m.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (m *Miu) Close() error {
	return m.client.Close()
}

// dialLane opens the outer connection of a lane: TCP through the proxy's dialer, then TLS, uTLS or
// REALITY. The TLS connection is returned as it is, without any wrapper around it: the library needs
// to reach into it for raw segments.
func (m *Miu) dialLane(ctx context.Context) (net.Conn, error) {
	conn, err := m.dialer.DialContext(ctx, "tcp", m.addr)
	if err != nil {
		return nil, err
	}
	tlsConn, err := vmess.StreamTLSConn(ctx, conn, m.tlsConfig)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// miuRawUsable checks, once, that the library's raw segments work on the two kinds of TLS connection
// vmess.StreamTLSConn can return here: *tls.Conn of metacubex/tls and *utls.UConn of metacubex/utls
// (the latter is also what a REALITY handshake yields).
var miuRawUsable = once.OnceValue(func() bool {
	err := miu.SelfTest(func(conn net.Conn, cfg *stdtls.Config) net.Conn {
		return tls.Client(conn, &tls.Config{ServerName: cfg.ServerName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	})
	if err == nil {
		err = miu.SelfTest(func(conn net.Conn, cfg *stdtls.Config) net.Conn {
			chrome, _ := tlsC.GetFingerprint("chrome")
			return tlsC.UClient(conn, &tlsC.Config{ServerName: cfg.ServerName, InsecureSkipVerify: true, MinVersion: tlsC.VersionTLS13}, chrome)
		})
	}
	if err != nil {
		log.Warnln("Miu: raw segments are not usable with this build, continuing without them: %v", err)
		return false
	}
	return true
})

func NewMiu(option MiuOption) (*Miu, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Miu{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Miu,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	realityConfig, err := option.RealityOpts.Parse()
	if err != nil {
		return nil, err
	}
	if realityConfig != nil && option.ClientFingerprint == "" {
		return nil, errors.New("miu: reality-opts needs client-fingerprint")
	}
	sni := option.SNI
	if sni == "" {
		sni = option.ServerName
	}
	if sni == "" {
		sni = option.Server
	}
	outbound.tlsConfig = &vmess.TLSConfig{
		Host:              sni,
		SkipCertVerify:    option.SkipCertVerify,
		FingerPrint:       option.Fingerprint,
		NextProtos:        option.ALPN,
		ClientFingerprint: option.ClientFingerprint,
		Reality:           realityConfig,
	}

	outbound.client, err = miu.NewClient(miu.ClientConfig{
		PSK:           option.PSK,
		Dial:          outbound.dialLane,
		LaneIdle:      time.Duration(option.IdleSessionTimeout) * time.Second,
		MinIdle:       option.MinIdleSession,
		DisableRaw:    !miuRawUsable(),
		PaddingScheme: strings.Join(option.PaddingScheme, "\n"),
	})
	if err != nil {
		return nil, err
	}
	return outbound, nil
}
