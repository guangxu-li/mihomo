package outbound

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestRedactWireGuardIpcConf(t *testing.T) {
	priv := strings.Repeat("a", 64)
	psk1 := strings.Repeat("b", 64)
	psk2 := strings.Repeat("c", 64)
	hpk := strings.Repeat("d", 64)
	pub1 := strings.Repeat("1", 64)
	pub2 := strings.Repeat("2", 64)

	conf := strings.Join([]string{
		"private_key=" + priv,
		"listen_port=51900",
		"header_protection_key=" + hpk,
		"public_key=" + pub1,
		"endpoint=127.0.0.1:51901",
		"preshared_key=" + psk1,
		"allowed_ip=10.8.0.2/32",
		"persistent_keepalive_interval=25",
		"public_key=" + pub2,
		"preshared_key=" + psk2,
		"allowed_ip=fd00:8::3/128",
		"",
	}, "\n")

	got := redactWireGuardIpcConf(conf)
	for _, secret := range []string{priv, psk1, psk2, hpk} {
		require.NotContains(t, got, secret)
	}

	want := strings.Join([]string{
		"private_key=<redacted>",
		"listen_port=51900",
		"header_protection_key=<redacted>",
		"public_key=" + pub1,
		"endpoint=127.0.0.1:51901",
		"preshared_key=<redacted>",
		"allowed_ip=10.8.0.2/32",
		"persistent_keepalive_interval=25",
		"public_key=" + pub2,
		"preshared_key=<redacted>",
		"allowed_ip=fd00:8::3/128",
		"",
	}, "\n")
	require.Equal(t, want, got)

	require.Equal(t, "", redactWireGuardIpcConf(""))
	require.Equal(t, "private_key=<redacted>", redactWireGuardIpcConf("private_key="+priv))
}

func TestRedactGeneratedWireGuardIpcConf(t *testing.T) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	peerKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	var pskBytes [32]byte
	_, err = rand.Read(pskBytes[:])
	require.NoError(t, err)

	w, err := NewWireGuard(WireGuardOption{
		Name:       "wg-redact",
		Ip:         "10.8.0.1",
		PrivateKey: base64.StdEncoding.EncodeToString(privKey.Bytes()),
		WireGuardPeerOption: WireGuardPeerOption{
			Server:       "127.0.0.1",
			Port:         51900,
			PublicKey:    base64.StdEncoding.EncodeToString(peerKey.PublicKey().Bytes()),
			PreSharedKey: base64.StdEncoding.EncodeToString(pskBytes[:]),
			AllowedIPs:   []string{"10.8.0.2/32"},
		},
	})
	require.NoError(t, err)
	defer w.Close()

	w.serverAddrMap = make(map[M.Socksaddr]netip.AddrPort)
	raw, err := w.genIpcConf(context.Background(), false)
	require.NoError(t, err)

	got := redactWireGuardIpcConf(raw)
	require.NotContains(t, got, hex.EncodeToString(privKey.Bytes()))
	require.NotContains(t, got, hex.EncodeToString(pskBytes[:]))
	require.Contains(t, got, "private_key=<redacted>\n")
	require.Contains(t, got, "preshared_key=<redacted>\n")
	require.Contains(t, got, "public_key="+hex.EncodeToString(peerKey.PublicKey().Bytes())+"\n")
}
