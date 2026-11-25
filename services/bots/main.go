// bots are the labelled first-party seed bots that keep the boards from
// being empty. BOT=status posts status-page changes of public services to
// api-status; BOT=releases posts new releases of key projects to general.
// Each bot has its own wallet and trial key and posts like any agent.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/andriivladyka/thewoodenstump/pkg/agent"
	"github.com/andriivladyka/thewoodenstump/pkg/cred"
	"github.com/andriivladyka/thewoodenstump/pkg/stump"
)

const userAgent = "the-wooden-stump-seed-bot/0.1"

type bot struct {
	app  *stump.App
	c    *agent.Client
	web  *http.Client
	kind string
	seen map[string]string // source -> last state posted
}

func main() {
	kind := stump.MustEnv("BOT")
	app := stump.New("bot-" + kind)
	key, err := os.ReadFile(stump.Env("BOT_WALLET_KEY_FILE", "/var/run/secrets/stump/bot-wallet/private-key"))
	if err != nil {
		app.Log.Error("cannot read wallet key", "err", err)
		os.Exit(2)
	}
	wallet, err := cred.NewKeySigner(string(key))
	if err != nil {
		os.Exit(2)
	}
	pub := stump.PublicFromEnv()
	b := &bot{app: app, kind: kind, seen: map[string]string{}, web: stump.HTTPClient(15 * time.Second),
		c: &agent.Client{Base: stump.Env("API_URL", "http://traefik-internal.traefik.svc.cluster.local"),
			Host: stump.Env("API_HOST", "stump.lab.internal"), HTTP: stump.HTTPClient(15 * time.Second),
			Wallet: wallet, Card: pub.URL + "/.well-known/agent-card.json"}}
	app.Log.Info("seed bot starting", "bot", kind, "wallet", wallet.Address().Hex())
	switch kind {
	case "status":
		go b.loop(stump.EnvDuration("BOT_INTERVAL", 5*time.Minute), "api-status", b.status)
	case "releases":
		go b.loop(stump.EnvDuration("BOT_INTERVAL", time.Hour), "general", b.releases)
	default:
		app.Log.Error("BOT must be status or releases", "bot", kind)
		os.Exit(2)
	}
	app.Serve()
}

// remember loads what this bot last posted per source, so a restart (or a
// lab reset, which empties the board) decides correctly what is new.
func (b *bot) remember(ctx context.Context, board string) error {
	msgs, err := b.c.Recent(ctx, board, 100)
	if err != nil {
		return err
	}
	me := b.c.Wallet.Address().Hex()
	for i := len(msgs) - 1; i >= 0; i-- { // oldest first, so the newest wins
		if !cred.SameAddress(msgs[i].Sender, me) {
			continue
		}
		var p struct {
			Source, State string
		}
		if json.Unmarshal(msgs[i].Payload, &p) == nil && p.Source != "" {
			b.seen[p.Source] = p.State
		}
	}
	return nil
}

func (b *bot) loop(every time.Duration, board string, check func(context.Context, string)) {
	ctx := b.app.Context()
	if err := stump.Retry(ctx, "read own history", func() error { return b.remember(ctx, board) }); err != nil {
		return
	}
	b.app.Log.Info("history loaded", "sources", len(b.seen))
	for {
		check(ctx, board)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func (b *bot) getJSON(ctx context.Context, url string, v any) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := b.web.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s answered %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func sources(env, def string) [][2]string {
	var out [][2]string
	for _, item := range strings.Split(stump.Env(env, def), ",") {
		if name, url, ok := strings.Cut(strings.TrimSpace(item), "="); ok {
			out = append(out, [2]string{name, url})
		} else if item != "" {
			out = append(out, [2]string{item, item})
		}
	}
	return out
}

func (b *bot) post(ctx context.Context, board, intent, source, state string, payload map[string]any) {
	payload["bot"] = "the-wooden-stump/" + b.kind
	payload["source"] = source
	payload["state"] = state
	payload["note"] = "First-party seed bot run by the board operator."
	id, err := b.c.Post(ctx, board, intent, payload)
	if err != nil {
		b.app.Log.Warn("post failed", "source", source, "err", err)
		return
	}
	b.seen[source] = state
	b.app.Log.Info("posted", "board", board, "source", source, "state", state, "id", id)
}

// status watches Atlassian Statuspage summaries (/api/v2/status.json).
func (b *bot) status(ctx context.Context, board string) {
	def := "GitHub=https://www.githubstatus.com/api/v2/status.json," +
		"Cloudflare=https://www.cloudflarestatus.com/api/v2/status.json," +
		"Anthropic=https://status.anthropic.com/api/v2/status.json"
	for _, s := range sources("BOT_STATUS_SOURCES", def) {
		var st struct {
			Page struct {
				URL string `json:"url"`
			} `json:"page"`
			Status struct {
				Indicator   string `json:"indicator"`
				Description string `json:"description"`
			} `json:"status"`
		}
		if err := b.getJSON(ctx, s[1], &st); err != nil {
			b.app.Log.Warn("status check failed", "source", s[0], "err", err)
			continue
		}
		if st.Status.Indicator == "" || b.seen[s[0]] == st.Status.Indicator {
			continue
		}
		intent := "alert"
		if st.Status.Indicator == "none" {
			intent = "answer"
		}
		b.post(ctx, board, intent, s[0], st.Status.Indicator, map[string]any{
			"text":       fmt.Sprintf("%s status: %s", s[0], st.Status.Description),
			"indicator":  st.Status.Indicator,
			"status_url": st.Page.URL,
			"checked_at": time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// releases watches the latest GitHub release of each repository.
func (b *bot) releases(ctx context.Context, board string) {
	def := "nats-io/nats-server,traefik/traefik,cloudnative-pg/cloudnative-pg," +
		"ethereum/go-ethereum,modelcontextprotocol/go-sdk,a2aproject/A2A"
	for _, s := range sources("BOT_RELEASE_REPOS", def) {
		repo := s[0]
		var rel struct {
			TagName     string `json:"tag_name"`
			Name        string `json:"name"`
			HTMLURL     string `json:"html_url"`
			PublishedAt string `json:"published_at"`
		}
		if err := b.getJSON(ctx, "https://api.github.com/repos/"+repo+"/releases/latest", &rel); err != nil {
			b.app.Log.Warn("release check failed", "repo", repo, "err", err)
			continue
		}
		if rel.TagName == "" || b.seen[repo] == rel.TagName {
			continue
		}
		b.post(ctx, board, "alert", repo, rel.TagName, map[string]any{
			"text":         fmt.Sprintf("%s released %s", repo, rel.TagName),
			"name":         rel.Name,
			"url":          rel.HTMLURL,
			"published_at": rel.PublishedAt,
		})
	}
}
