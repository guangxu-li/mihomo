package executor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func TestApplyConfigWaitsForParse(t *testing.T) {
	home, general := C.Path.HomeDir(), GetGeneral()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() {
		updateGeneral(general, false)
		C.SetHomeDir(home)
	})
	const blank = "log-level: silent\nprofile: {store-selected: false}\n"
	parse := func(yaml string) *config.Config {
		cfg, err := ParseWithBytes([]byte(blank + yaml))
		require.NoError(t, err)
		return cfg
	}
	ApplyConfig(parse("geodata-mode: false\nglobal-ua: before\n"), false)
	cfg := parse("geodata-mode: false\nglobal-ua: applied\n")

	// The parse of a third config, with another geodata mode, waits for its geodata download.
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(entered) })
		<-release
		w.Header().Set("Content-Length", "8") // more than follows, so the download fails
		_, _ = w.Write([]byte("x"))
	}))
	defer server.Close()
	rejected := make(chan error, 1)
	go func() {
		_, err := ParseWithBytes([]byte(fmt.Sprintf(blank+"geodata-mode: true\ngeox-url: {geoip: %[1]q, geosite: %[1]q, mmdb: %[1]q, asn: %[1]q}\nrules: ['GEOIP,CN,DIRECT']\n", server.URL)))
		rejected <- err
	}()
	select {
	case <-entered:
	case err := <-rejected:
		close(release)
		t.Fatalf("the parse ended before its geodata download: %v", err)
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatalf("the parse did not download geodata: %v", <-rejected)
	}

	// Meanwhile a config that omits the geodata mode is parsed, and cfg is applied.
	var other *config.Config
	omitted := make(chan error, 1)
	go func() {
		var err error
		other, err = ParseWithBytes([]byte(blank))
		omitted <- err
	}()
	applied := make(chan struct{})
	go func() {
		ApplyConfig(cfg, false)
		close(applied)
	}()
	select {
	case <-applied:
		t.Error("ApplyConfig ran while another config was parsed")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	err, omittedErr := <-rejected, <-omitted
	<-applied
	require.Error(t, err)
	require.NoError(t, omittedErr)
	require.False(t, other.General.GeodataMode, "the default came from a config that was only parsed")
	require.Equal(t, "applied", GetGeneral().GlobalUA, "a parse put settings back over the applied ones")
}
