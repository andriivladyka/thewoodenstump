package stump

import (
	"context"
	"strings"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"github.com/ethereum/go-ethereum/common"
)

// Gauges refreshes gauges every minute from fn, which returns full metric
// names (with labels) and their values. Scrapes read the last values, so a
// slow query never holds up /metrics. A gauge fn stops returning keeps its
// last value; return it as 0 to reset it.
func (a *App) Gauges(fn func(ctx context.Context) (map[string]float64, error)) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			ctx, cancel := context.WithTimeout(a.ctx, 20*time.Second)
			vals, err := fn(ctx)
			cancel()
			if err != nil {
				a.Log.Warn("gauges not refreshed", "err", err)
			}
			for name, v := range vals {
				metrics.GetOrCreateGauge(name, nil).Set(v)
			}
			select {
			case <-a.ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// FirstParty lists the wallets on TRIAL_ALLOWLIST (the operator's bots and
// tests), lower-cased, so activity metrics can tell them from real users.
func FirstParty() []string {
	var out []string
	for _, a := range strings.FieldsFunc(Env("TRIAL_ALLOWLIST", ""), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if common.IsHexAddress(a) {
			out = append(out, strings.ToLower(common.HexToAddress(a).Hex()))
		}
	}
	return out
}
