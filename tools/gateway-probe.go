// Disposable packet probe for the two-network gateway lab. No live credentials.
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("missing mode")
	}
	if os.Args[1] == "serve" {
		for _, port := range []string{"8080", "8082"} {
			go http.ListenAndServe(":"+port, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.RemoteAddr) }))
		}
		u, e := net.ListenPacket("udp4", ":8081")
		if e != nil {
			return e
		}
		defer u.Close()
		for {
			b := make([]byte, 4096)
			_, p, e := u.ReadFrom(b)
			if e != nil {
				return e
			}
			u.WriteTo([]byte(p.String()), p)
		}
	}
	if len(os.Args) < 3 {
		return fmt.Errorf("missing address")
	}
	mode, addr := os.Args[1], os.Args[2]
	if mode == "tcp-held" {
		c, e := net.DialTimeout("tcp", addr, 4*time.Second)
		if e != nil {
			return e
		}
		defer c.Close()
		r := bufio.NewReader(c)
		request := func() error {
			c.SetDeadline(time.Now().Add(4 * time.Second))
			if _, e := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: probe\r\n\r\n"); e != nil {
				return e
			}
			resp, e := http.ReadResponse(r, nil)
			if e != nil {
				return e
			}
			defer resp.Body.Close()
			_, e = io.Copy(io.Discard, resp.Body)
			return e
		}
		if e = request(); e != nil {
			return e
		}
		if e = os.WriteFile("/run/probe-ready", []byte("connected"), 0600); e != nil {
			return e
		}
		deadline := time.Now().Add(30 * time.Second)
		for {
			if _, e = os.Stat("/run/probe-continue"); e == nil {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("revocation signal timed out")
			}
			time.Sleep(100 * time.Millisecond)
		}
		if request() == nil {
			return fmt.Errorf("established connection survived revocation")
		}
		fmt.Println("established flow revoked")
		return nil
	}
	if mode == "tcp" {
		c := http.Client{Timeout: 4 * time.Second}
		r, e := c.Get("http://" + addr)
		if e != nil {
			return e
		}
		defer r.Body.Close()
		b, e := io.ReadAll(r.Body)
		fmt.Println(string(b))
		return e
	}
	if mode == "udp" {
		c, e := net.DialTimeout("udp", addr, time.Second)
		if e != nil {
			return e
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("probe"))
		b := make([]byte, 256)
		n, e := c.Read(b)
		fmt.Println(string(b[:n]))
		return e
	}
	if strings.HasPrefix(mode, "dns-") && len(os.Args) == 5 {
		q := make([]byte, 12)
		q[0] = 27
		q[2] = 1
		q[5] = 1
		for _, part := range strings.Split(os.Args[3], ".") {
			q = append(q, byte(len(part)))
			q = append(q, part...)
		}
		kind := byte(1)
		if os.Args[4] == "AAAA" {
			kind = 28
		}
		q = append(q, 0, 0, kind, 0, 1)
		network := strings.TrimPrefix(mode, "dns-")
		c, e := net.DialTimeout(network, addr, time.Second)
		if e != nil {
			return e
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(4 * time.Second))
		var b []byte
		if network == "tcp" {
			f := make([]byte, 2)
			binary.BigEndian.PutUint16(f, uint16(len(q)))
			c.Write(append(f, q...))
			if _, e = io.ReadFull(c, f); e != nil {
				return e
			}
			b = make([]byte, binary.BigEndian.Uint16(f))
			_, e = io.ReadFull(c, b)
		} else {
			c.Write(q)
			b = make([]byte, 4096)
			var n int
			n, e = c.Read(b)
			b = b[:n]
		}
		if e != nil {
			return e
		}
		if len(b) < 12 {
			return fmt.Errorf("short DNS")
		}
		fmt.Printf("rcode=%d answers=%d bytes=%x\n", b[3]&15, binary.BigEndian.Uint16(b[6:8]), b)
		return nil
	}
	return fmt.Errorf("unknown mode")
}
