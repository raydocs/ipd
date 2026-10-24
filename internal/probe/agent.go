package probe

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/coder/websocket"
)

// HandleTask runs one signed payload on the probe. The default echoes it.
type HandleTask func(payload []byte) ([]byte, error)

// RunAgent dials the hub and serves signed tasks until ctx ends.
// It refuses a task whose signature does not match the hub key from enroll.
func RunAgent(ctx context.Context, wsURL, token, name string, handle HandleTask) error {
	if handle == nil {
		handle = func(payload []byte) ([]byte, error) { return payload, nil }
	}
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return err
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	hello, _ := json.Marshal(envelope{Op: "hello", Token: token, Name: name})
	if err := c.Write(ctx, websocket.MessageText, hello); err != nil {
		return err
	}
	var pub string
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return err
		}
		var env envelope
		if json.Unmarshal(data, &env) != nil {
			continue
		}
		switch env.Op {
		case "enrolled":
			pub = env.HubPub
		case "task":
			payload, err := hex.DecodeString(env.Payload)
			sig, err2 := hex.DecodeString(env.Sig)
			if err != nil || err2 != nil || !Verify(pub, payload, sig) {
				body, _ := json.Marshal(envelope{Op: "result", ID: env.ID, OK: false, Error: "bad signature"})
				_ = c.Write(ctx, websocket.MessageText, body)
				continue
			}
			out, herr := handle(payload)
			res := envelope{Op: "result", ID: env.ID, OK: herr == nil, Body: out}
			if herr != nil {
				res.Error = herr.Error()
			}
			b, _ := json.Marshal(res)
			if err := c.Write(ctx, websocket.MessageText, b); err != nil {
				return err
			}
		case "error":
			return httpError(env.Error)
		}
	}
}

type httpError string

func (e httpError) Error() string { return string(e) }

// Enroll asks the hub for its public key.
func Enroll(ctx context.Context, base, token string) (string, error) {
	raw, _ := json.Marshal(map[string]string{"token": token})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/agent/enroll", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var body struct {
		HubPub string `json:"hub_pub"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", err
	}
	return body.HubPub, nil
}
