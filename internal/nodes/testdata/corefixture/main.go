// corefixture is a local mixed-proxy wiring fixture, NOT a real proxy core.
// It reads the actual backend CLI/config and never connects to an upstream server.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	// Task-owned persistent launch audit, outside the runner-owned tempdir, lets
	// rejection tests prove no subprocess was spawned and then merely cleaned up.
	audit, err := os.OpenFile(filepath.Join(filepath.Dir(os.Args[0]), "fixture-starts"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(37)
	}
	_, err = audit.WriteString("start\n")
	audit.Close()
	if err != nil {
		os.Exit(38)
	}

	dir := flag.String("d", "", "home")
	file := flag.String("f", "", "config")
	validate := flag.Bool("t", false, "validate only")
	isSingBox := len(os.Args) > 1 && os.Args[1] == "run"
	if isSingBox {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
	flag.StringVar(dir, "D", "", "home (sing-box)")
	flag.StringVar(file, "c", "", "config (sing-box)")
	flag.Parse()
	if *validate {
		return
	} // Exercises the old validation-only runner's gap.
	data, err := os.ReadFile(*file)
	if err != nil {
		panic(err)
	}
	var cfg struct {
		Proxies   []map[string]any `yaml:"proxies"`
		Listeners []struct {
			Type   string `yaml:"type"`
			Listen string `yaml:"listen"`
			Port   int    `yaml:"port"`
			Proxy  string `yaml:"proxy"`
			Users  []struct {
				Username string `yaml:"username"`
				Password string `yaml:"password"`
			} `yaml:"users"`
		} `yaml:"listeners"`
	}
	if isSingBox {
		var sb struct {
			Outbounds []map[string]any `json:"outbounds"`
			Inbounds  []struct {
				Type   string `json:"type"`
				Listen string `json:"listen"`
				Port   int    `json:"listen_port"`
				Users  []struct {
					Username string `json:"username"`
					Password string `json:"password"`
				} `json:"users"`
			} `json:"inbounds"`
			Route struct {
				Final string `json:"final"`
			} `json:"route"`
		}
		if json.Unmarshal(data, &sb) != nil || len(sb.Outbounds) != 1 || len(sb.Inbounds) != 1 {
			os.Exit(35)
		}
		// Translate only the fixture's local view, never the generated file.
		normalized := map[string]any{"proxies": sb.Outbounds, "listeners": []any{map[string]any{"type": sb.Inbounds[0].Type, "listen": sb.Inbounds[0].Listen, "port": sb.Inbounds[0].Port, "proxy": sb.Route.Final, "users": sb.Inbounds[0].Users}}}
		encoded, _ := json.Marshal(normalized)
		if yaml.Unmarshal(encoded, &cfg) != nil {
			os.Exit(36)
		}
		cfg.Proxies[0]["name"] = cfg.Proxies[0]["tag"]
	} else if yaml.Unmarshal(data, &cfg) != nil {
		os.Exit(31)
	}
	if len(cfg.Proxies) != 1 || len(cfg.Listeners) != 1 {
		os.Exit(31)
	}
	p, l := cfg.Proxies[0], cfg.Listeners[0]
	if l.Type != "mixed" || l.Listen != "127.0.0.1" || l.Port == 0 || l.Proxy != p["name"] || len(l.Users) != 1 {
		os.Exit(32)
	}
	state, _ := json.Marshal(map[string]any{"pid": os.Getpid(), "env": os.Environ(), "config": *file})
	if os.WriteFile(filepath.Join(*dir, "fixture-state.json"), state, 0600) != nil {
		os.Exit(33)
	}
	mode, _ := p["password"].(string)
	if mode == "fixture-exit" {
		fmt.Fprintln(os.Stderr, "credential-secret server-secret config-secret")
		os.Exit(42)
	}
	if mode == "fixture-stall" {
		for {
			time.Sleep(time.Hour)
		}
	}
	if mode == "fixture-delay-bind" {
		time.Sleep(300 * time.Millisecond)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(l.Listen, strconv.Itoa(l.Port)))
	if err != nil {
		os.Exit(34)
	}
	if mode == "fixture-late-exit" {
		go func() { time.Sleep(800 * time.Millisecond); os.Exit(43) }()
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go serve(c, l.Users[0].Username, l.Users[0].Password, fmt.Sprint(p["server"]), mode)
	}
}

func serve(c net.Conn, user, pass, marker, mode string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(c)
	b, err := r.Peek(1)
	if err != nil {
		return
	}
	if b[0] == 5 {
		head := make([]byte, 2)
		if _, err = io.ReadFull(r, head); err != nil {
			return
		}
		methods := make([]byte, int(head[1]))
		if _, err = io.ReadFull(r, methods); err != nil {
			return
		}
		if mode == "fixture-collision" {
			_, _ = c.Write([]byte{5, 0})
			return
		}
		_, _ = c.Write([]byte{5, 2})
		if _, err = io.ReadFull(r, head); err != nil {
			return
		}
		u := make([]byte, int(head[1]))
		if _, err = io.ReadFull(r, u); err != nil {
			return
		}
		n, err := r.ReadByte()
		if err != nil {
			return
		}
		pw := make([]byte, int(n))
		if _, err = io.ReadFull(r, pw); err != nil {
			return
		}
		if string(u) != user || string(pw) != pass {
			_, _ = c.Write([]byte{1, 1})
			return
		}
		_, _ = c.Write([]byte{1, 0})
		// A local test CONNECT returns an identity marker, not an upstream connection.
		head = make([]byte, 4)
		if _, err = io.ReadFull(r, head); err != nil {
			return
		}
		switch head[3] {
		case 1:
			head = make([]byte, 6)
		case 3:
			n, err := r.ReadByte()
			if err != nil {
				return
			}
			head = make([]byte, int(n)+2)
		case 4:
			head = make([]byte, 18)
		default:
			return
		}
		if _, err = io.ReadFull(r, head); err != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		_, _ = fmt.Fprint(c, marker)
		return
	}
	if mode == "fixture-socks-only" {
		return
	}
	req, err := http.ReadRequest(r)
	if err != nil {
		return
	}
	defer req.Body.Close()
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	status, body := 200, marker
	if req.Header.Get("Proxy-Authorization") != auth {
		_ = os.WriteFile(filepath.Join(os.Getenv("TMPDIR"), "r2-http-probed"), []byte("ready"), 0600)
		status, body = 407, ""
	} else if req.URL.Scheme == "" || req.URL.Host == "" {
		status, body = 400, ""
	}
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body), strings.TrimSpace(body))
}
