// egressfixture is a loopback-only mixed HTTP/SOCKS tunnel, NOT a real core.
// It reads the runner's actual private configuration and backend CLI. Only the
// configured loopback test origin can be dialed; request destinations are never
// dialed. HTTPS and response parsing are performed by the real app client.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type user struct {
	Username string
	Password string
}

func main() {
	file, dir := "", ""
	for i := 1; i+1 < len(os.Args); i++ {
		switch os.Args[i] {
		case "-f", "-c":
			file = os.Args[i+1]
		case "-d", "-D":
			dir = os.Args[i+1]
		}
	}
	data, e := os.ReadFile(file)
	if e != nil {
		os.Exit(2)
	}
	var d map[string]any
	if yaml.Unmarshal(data, &d) != nil {
		os.Exit(3)
	}
	sing := len(os.Args) > 1 && os.Args[1] == "run"
	key, inKey, portKey, nameKey := "proxies", "listeners", "port", "name"
	if sing {
		key, inKey, portKey, nameKey = "outbounds", "inbounds", "listen_port", "tag"
	}
	list, ok := d[key].([]any)
	if !ok || len(list) != 1 {
		os.Exit(4)
	}
	p := list[0].(map[string]any)
	ins := d[inKey].([]any)
	if len(ins) != 1 {
		os.Exit(5)
	}
	in := ins[0].(map[string]any)
	if p[nameKey] != "ipd-node" || in["listen"] != "127.0.0.1" {
		os.Exit(6)
	}
	if sing {
		if d["route"].(map[string]any)["final"] != "ipd-node" {
			os.Exit(7)
		}
	} else if in["proxy"] != "ipd-node" {
		os.Exit(8)
	}
	users := in["users"].([]any)
	if len(users) != 1 {
		os.Exit(9)
	}
	credentials := users[0].(map[string]any)
	u, pw := credentials["username"].(string), credentials["password"].(string)
	port := in[portKey].(int)
	server := p["server"].(string)
	outPortKey := "port"
	if sing {
		outPortKey = "server_port"
	}
	origin := net.JoinHostPort(server, strconv.Itoa(p[outPortKey].(int)))
	if server != "127.0.0.1" {
		os.Exit(10)
	}
	mode, _ := p["password"].(string)
	audit, _ := os.OpenFile(filepath.Join(filepath.Dir(os.Args[0]), "egress-audit.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if audit == nil {
		os.Exit(11)
	}
	json.NewEncoder(audit).Encode(map[string]any{"pid": os.Getpid(), "dir": dir, "env": os.Environ(), "origin": origin, "backend": sing})
	audit.Close()
	if mode == "exit-start" {
		os.Exit(12)
	}
	ln, e := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if e != nil {
		os.Exit(13)
	}
	for {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		go serve(c, u, pw, origin, mode)
	}
}
func serve(c net.Conn, u, pw, origin, mode string) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(c)
	b, e := r.Peek(1)
	if e != nil {
		return
	}
	if b[0] == 5 {
		h := make([]byte, 2)
		if _, e = io.ReadFull(r, h); e != nil {
			return
		}
		methods := make([]byte, int(h[1]))
		if _, e = io.ReadFull(r, methods); e != nil {
			return
		}
		c.Write([]byte{5, 2})
		if _, e = io.ReadFull(r, h); e != nil {
			return
		}
		name := make([]byte, int(h[1]))
		if _, e = io.ReadFull(r, name); e != nil {
			return
		}
		n, e := r.ReadByte()
		if e != nil {
			return
		}
		pass := make([]byte, int(n))
		if _, e = io.ReadFull(r, pass); e != nil {
			return
		}
		if string(name) != u || string(pass) != pw {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
		h = make([]byte, 4)
		if _, e = io.ReadFull(r, h); e != nil {
			return
		}
		size := 0
		switch h[3] {
		case 1:
			size = 4
		case 4:
			size = 16
		case 3:
			n, e := r.ReadByte()
			if e != nil {
				return
			}
			size = int(n)
		default:
			return
		}
		dest := make([]byte, size+2)
		if _, e = io.ReadFull(r, dest); e != nil {
			return
		}
		_ = binary.BigEndian.Uint16(dest[len(dest)-2:])
		if mode == "reject" {
			c.Write([]byte{5, 5, 0, 1, 127, 0, 0, 1, 0, 0})
			return
		}
		upstream, e := net.DialTimeout("tcp", origin, time.Second)
		if e != nil {
			return
		}
		defer upstream.Close()
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		tunnel(c, r, upstream, mode)
		return
	}
	req, e := http.ReadRequest(r)
	if e != nil {
		return
	}
	defer req.Body.Close()
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+pw))
	if req.Header.Get("Proxy-Authorization") != auth {
		fmt.Fprint(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if req.Method != "CONNECT" || mode == "reject" {
		fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	upstream, e := net.DialTimeout("tcp", origin, time.Second)
	if e != nil {
		fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()
	fmt.Fprint(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	tunnel(c, r, upstream, mode)
}
func tunnel(c net.Conn, r *bufio.Reader, upstream net.Conn, mode string) {
	if mode == "stall-connect" {
		os.WriteFile(filepath.Join(filepath.Dir(os.Args[0]), "connected"), []byte("ready"), 0600)
		time.Sleep(15 * time.Second)
		return
	}
	if mode == "exit-connect" {
		go func() { time.Sleep(100 * time.Millisecond); os.Exit(14) }()
	}
	done := make(chan struct{})
	go func() { io.Copy(upstream, r); close(done) }()
	io.Copy(c, upstream)
	c.Close()
	upstream.Close()
	<-done
}
