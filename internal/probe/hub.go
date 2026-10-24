package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Hub accepts outbound probe agents. Tasks are signed with an Ed25519 key
// the agent learns at hello time. The agent never dials a user-supplied URL.
type Hub struct {
	Token string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey

	mu    sync.Mutex
	conns map[string]*agentConn
}

type agentConn struct {
	name string
	c    *websocket.Conn
	send chan []byte
}

type envelope struct {
	Op      string          `json:"op"`
	Token   string          `json:"token,omitempty"`
	Name    string          `json:"name,omitempty"`
	ID      string          `json:"id,omitempty"`
	Payload string          `json:"payload,omitempty"`
	Sig     string          `json:"sig,omitempty"`
	HubPub  string          `json:"hub_pub,omitempty"`
	OK      bool            `json:"ok,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// NewHub generates a signing key for this process.
func NewHub(token string) *Hub {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &Hub{Token: token, priv: priv, pub: pub, conns: map[string]*agentConn{}}
}

// PublicKeyHex is what an agent pins.
func (h *Hub) PublicKeyHex() string { return hex.EncodeToString(h.pub) }

// ServeHTTP handles /agent/enroll and the websocket at /agent.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/agent/enroll":
		var body struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if h.Token != "" && body.Token != h.Token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"hub_pub": h.PublicKeyHex()})
	default:
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		h.readLoop(r.Context(), c)
	}
}

func (h *Hub) readLoop(ctx context.Context, c *websocket.Conn) {
	defer c.Close(websocket.StatusNormalClosure, "")
	var name string
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			if name != "" {
				h.mu.Lock()
				delete(h.conns, name)
				h.mu.Unlock()
			}
			return
		}
		var env envelope
		if json.Unmarshal(data, &env) != nil {
			continue
		}
		switch env.Op {
		case "hello":
			if h.Token != "" && env.Token != h.Token {
				_ = writeEnv(ctx, c, envelope{Op: "error", Error: "unauthorized"})
				return
			}
			name = env.Name
			if name == "" {
				name = "agent"
			}
			ac := &agentConn{name: name, c: c, send: make(chan []byte, 4)}
			h.mu.Lock()
			h.conns[name] = ac
			h.mu.Unlock()
			_ = writeEnv(ctx, c, envelope{Op: "enrolled", HubPub: h.PublicKeyHex(), Name: name})
		case "result":
			h.mu.Lock()
			ac := h.conns[name]
			h.mu.Unlock()
			if ac != nil {
				select {
				case ac.send <- data:
				default:
				}
			}
		}
	}
}

// Dispatch sends a signed task to a connected agent and waits for the result.
func (h *Hub) Dispatch(ctx context.Context, agent string, payload []byte) (json.RawMessage, error) {
	h.mu.Lock()
	ac := h.conns[agent]
	h.mu.Unlock()
	if ac == nil {
		return nil, errNoAgent
	}
	sig := ed25519.Sign(h.priv, payload)
	env := envelope{Op: "task", ID: hex.EncodeToString(sig[:8]), Payload: hex.EncodeToString(payload), Sig: hex.EncodeToString(sig)}
	if err := writeEnv(ctx, ac.c, env); err != nil {
		return nil, err
	}
	select {
	case raw := <-ac.send:
		var back envelope
		if json.Unmarshal(raw, &back) != nil {
			return raw, nil
		}
		return back.Body, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Second):
		return nil, context.DeadlineExceeded
	}
}

func writeEnv(ctx context.Context, c *websocket.Conn, env envelope) error {
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, b)
}

type noAgentErr string

func (e noAgentErr) Error() string { return string(e) }

const errNoAgent noAgentErr = "no agent connected"

// Verify reports whether sig is a valid hub signature over payload.
func Verify(pubHex string, payload, sig []byte) bool {
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), payload, sig)
}
