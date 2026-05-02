// ©AngelaMos | 2026
// nvd_client.go

package cve

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"golang.org/x/time/rate"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/httpx"
)

const (
	defaultNVDBaseURL    = "https://services.nvd.nist.gov"
	pathNVDCVE2          = "/rest/json/cves/2.0"
	defaultNVDRate       = 600 * time.Millisecond
	defaultNVDBurst      = 5
	defaultNVDBudget     = 5
	defaultNVDBreakerWin = 120 * time.Second
	nvdTimeFormat        = "2006-01-02T15:04:05.000"
	nvdAPIKeyHeader      = "apiKey"
)

type NVDClientConfig struct {
	BaseURL string
	APIKey  string
}

type NVDClient struct {
	hx *httpx.Client
}

func NewNVDClient(cfg NVDClientConfig) *NVDClient {
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultNVDBaseURL
	}
	return &NVDClient{
		hx: httpx.New(httpx.Config{
			Name:                     "nvd",
			BaseURL:                  cfg.BaseURL,
			APIKey:                   cfg.APIKey,
			APIKeyHeader:             nvdAPIKeyHeader,
			Rate:                     rate.Every(defaultNVDRate),
			Burst:                    defaultNVDBurst,
			ConsecutiveFailureBudget: defaultNVDBudget,
			BreakerTimeout:           defaultNVDBreakerWin,
		}),
	}
}

type NVDResponse struct {
	ResultsPerPage  int           `json:"resultsPerPage"`
	StartIndex      int           `json:"startIndex"`
	TotalResults    int           `json:"totalResults"`
	Vulnerabilities []NVDVulnRoot `json:"vulnerabilities"`
}

type NVDVulnRoot struct {
	CVE NVDCVE `json:"cve"`
}

type NVDCVE struct {
	ID           string     `json:"id"`
	Published    NVDTime    `json:"published"`
	LastModified NVDTime    `json:"lastModified"`
	Metrics      NVDMetrics `json:"metrics"`
}

type NVDTime struct {
	time.Time
}

func (t *NVDTime) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if s == "" || s == "null" {
		return nil
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999",
		"2006-01-02T15:04:05",
	} {
		if parsed, err := time.Parse(layout, s); err == nil {
			t.Time = parsed.UTC()
			return nil
		}
	}
	return fmt.Errorf("nvd time: unrecognized format %q", s)
}

type NVDMetrics struct {
	CVSSv31 []NVDMetricEntry `json:"cvssMetricV31"`
	CVSSv30 []NVDMetricEntry `json:"cvssMetricV30"`
}

type NVDMetricEntry struct {
	CVSSData NVDCVSSData `json:"cvssData"`
}

type NVDCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

func (c *NVDClient) Fetch(ctx context.Context, start, end time.Time) (NVDResponse, error) {
	q := url.Values{
		"lastModStartDate": []string{start.UTC().Format(nvdTimeFormat)},
		"lastModEndDate":   []string{end.UTC().Format(nvdTimeFormat)},
	}
	var resp NVDResponse
	if err := c.hx.GetJSON(ctx, pathNVDCVE2, q, &resp); err != nil {
		return NVDResponse{}, fmt.Errorf("nvd fetch: %w", err)
	}
	return resp, nil
}

func (v NVDVulnRoot) PrimarySeverity() (float64, string) {
	if len(v.CVE.Metrics.CVSSv31) > 0 {
		return v.CVE.Metrics.CVSSv31[0].CVSSData.BaseScore, v.CVE.Metrics.CVSSv31[0].CVSSData.BaseSeverity
	}
	if len(v.CVE.Metrics.CVSSv30) > 0 {
		return v.CVE.Metrics.CVSSv30[0].CVSSData.BaseScore, v.CVE.Metrics.CVSSv30[0].CVSSData.BaseSeverity
	}
	return 0, ""
}
