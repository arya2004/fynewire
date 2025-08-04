package ai

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/arya2004/fynewire/internal/model"
	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// Chat abstracts a single long-running Gemini session.
type Chat interface {
	Reply(prompt string, pkts []model.Packet) ([]model.Packet, error)
}

var _ Chat = (*geminiChat)(nil)

// NewGemini defers heavy API init until the first call.
func NewGemini() Chat { return &geminiChat{} }

type geminiChat struct {
	once sync.Once
	chat *genai.ChatSession
	err  error
}

func (g *geminiChat) init() {
	key := os.Getenv("API_KEY")
	ctx := context.Background()

	cl, err := genai.NewClient(ctx, option.WithAPIKey(key))
	if err != nil {
		g.err = err
		return
	}
	m := cl.GenerativeModel("gemini-1.5-flash")

	// Register the filterPackets function so Gemini can call it.
	m.Tools = []*genai.Tool{{
		FunctionDeclarations: []*genai.FunctionDeclaration{{
			Name: "filterPackets",
			Parameters: &genai.Schema{
				Type: genai.TypeObject,
				Properties: map[string]*genai.Schema{
					"protocol": {}, "src_ip": {}, "dst_ip": {},
					"src_port": {}, "dst_port": {}, "free_text": {}, "limit": {},
				},
			},
		}},
	}}
	g.chat = m.StartChat()
}

func (g *geminiChat) Reply(prompt string, pkts []model.Packet) ([]model.Packet, error) {
	g.once.Do(g.init)
	if g.err != nil {
		return nil, g.err
	}
	ctx := context.Background()
	resp, err := g.chat.SendMessage(ctx, genai.Text(prompt))
	if err != nil || len(resp.Candidates) == 0 {
		return nil, err
	}
	part := resp.Candidates[0].Content.Parts[0]
	return interpret(part, pkts), nil
}

// ---------------- private helpers ----------------

func interpret(p genai.Part, pkts []model.Packet) []model.Packet {
	if fc, ok := p.(genai.FunctionCall); ok && fc.Name == "filterPackets" {
		get := func(k string) string {
			if v, ok := fc.Args[k].(string); ok {
				return v
			}
			return ""
		}
		limit := 0
		if f, ok := fc.Args["limit"].(float64); ok {
			limit = int(f)
		}
		return model.ApplyFilters(pkts, model.FilterArgs{
			Protocol: get("protocol"),
			SrcIP:    get("src_ip"),
			DstIP:    get("dst_ip"),
			SrcPort:  get("src_port"),
			DstPort:  get("dst_port"),
			FreeText: get("free_text"),
			Limit:    limit,
		})
	}

	// Gemini didn't call the function: treat the whole response as free-text filter.
	return model.ApplyFilters(pkts, model.FallbackFilter(fmt.Sprint(p)))
}
