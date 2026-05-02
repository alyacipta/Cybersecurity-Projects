// ©AngelaMos | 2026
// nvd_client_test.go

package cve_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/collectors/cve"
)

func TestNVDClient_FetchSendsAPIKeyAndDecodes(t *testing.T) {
	var sawKey, sawStart, sawEnd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawKey = r.Header.Get("apiKey")
		sawStart = r.URL.Query().Get("lastModStartDate")
		sawEnd = r.URL.Query().Get("lastModEndDate")
		body, err := os.ReadFile("testdata/nvd_2h_window.json")
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := cve.NewNVDClient(cve.NVDClientConfig{BaseURL: srv.URL, APIKey: "test-key"})

	end := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	start := end.Add(-2 * time.Hour)

	resp, err := c.Fetch(context.Background(), start, end)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Vulnerabilities)
	require.Equal(t, "test-key", sawKey)
	require.NotEmpty(t, sawStart)
	require.NotEmpty(t, sawEnd)
}

func TestNVDClient_PrimarySeverityFromV31(t *testing.T) {
	v := cve.NVDVulnRoot{CVE: cve.NVDCVE{
		ID: "CVE-2026-X",
		Metrics: cve.NVDMetrics{
			CVSSv31: []cve.NVDMetricEntry{
				{CVSSData: cve.NVDCVSSData{BaseScore: 9.8, BaseSeverity: "CRITICAL"}},
			},
		},
	}}
	score, sev := v.PrimarySeverity()
	require.InDelta(t, 9.8, score, 0.0001)
	require.Equal(t, "CRITICAL", sev)
}

func TestNVDClient_PrimarySeverityFallsBackToV30(t *testing.T) {
	v := cve.NVDVulnRoot{CVE: cve.NVDCVE{
		ID: "CVE-2018-X",
		Metrics: cve.NVDMetrics{
			CVSSv30: []cve.NVDMetricEntry{
				{CVSSData: cve.NVDCVSSData{BaseScore: 7.5, BaseSeverity: "HIGH"}},
			},
		},
	}}
	score, sev := v.PrimarySeverity()
	require.InDelta(t, 7.5, score, 0.0001)
	require.Equal(t, "HIGH", sev)
}

func TestNVDClient_PrimarySeverityZeroWhenMissing(t *testing.T) {
	v := cve.NVDVulnRoot{CVE: cve.NVDCVE{ID: "CVE-X"}}
	score, sev := v.PrimarySeverity()
	require.Zero(t, score)
	require.Empty(t, sev)
}
