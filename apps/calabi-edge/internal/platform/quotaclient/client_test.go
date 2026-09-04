package quotaclient

import "testing"

func TestConnLimitsFromJSON(t *testing.T) {
	cases := []struct {
		name                       string
		json                       string
		wantMax, wantTCP, wantHTTP int64
	}{
		{
			name:     "free plan",
			json:     `{"max_tunnels":1,"bandwidth_kbps":1024,"max_conns":10,"tcp_conn_rate_per_min":100,"http_conn_rate_per_min":600}`,
			wantMax:  10,
			wantTCP:  100,
			wantHTTP: 600,
		},
		{
			name:     "enterprise plan",
			json:     `{"max_conns":800,"tcp_conn_rate_per_min":1200,"http_conn_rate_per_min":12000}`,
			wantMax:  800,
			wantTCP:  1200,
			wantHTTP: 12000,
		},
		{
			name:     "custom plan: -1 sentinels map to unlimited (0)",
			json:     `{"max_conns":-1,"tcp_conn_rate_per_min":-1,"http_conn_rate_per_min":-1}`,
			wantMax:  0,
			wantTCP:  0,
			wantHTTP: 0,
		},
		{
			name:     "legacy plan without the keys → all unlimited",
			json:     `{"max_tunnels":5,"bandwidth_kbps":2048}`,
			wantMax:  0,
			wantTCP:  0,
			wantHTTP: 0,
		},
		{
			name:     "empty json → all unlimited",
			json:     ``,
			wantMax:  0,
			wantTCP:  0,
			wantHTTP: 0,
		},
		{
			name:     "string-typed values tolerated",
			json:     `{"max_conns":"50","tcp_conn_rate_per_min":"150","http_conn_rate_per_min":"1500"}`,
			wantMax:  50,
			wantTCP:  150,
			wantHTTP: 1500,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotMax, gotTCP, gotHTTP := connLimitsFromJSON(c.json)
			if gotMax != c.wantMax || gotTCP != c.wantTCP || gotHTTP != c.wantHTTP {
				t.Errorf("connLimitsFromJSON(%s) = (%d,%d,%d), want (%d,%d,%d)",
					c.json, gotMax, gotTCP, gotHTTP, c.wantMax, c.wantTCP, c.wantHTTP)
			}
		})
	}
}
