package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func fixture() Config {
	return Config{Role: "hosted", Hostname: "migration", LoginServer: "https://control.example.com", Pool: "100.80.0.0/16", Domain: "mesh.example.com", TransitAddress: "10.231.0.2", TransitPeer: "10.231.0.3"}
}
func TestConfigBoundaries(t *testing.T) {
	if e := fixture().validate(); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.Pool = "0.0.0.0/0" }, func(c *Config) { c.Pool = "100.64.0.0/10" }, func(c *Config) { c.Pool = "100.100.0.0/16" }, func(c *Config) { c.Pool = "100.80.0.1/16" },
		func(c *Config) { c.TransitPeer = c.TransitAddress }, func(c *Config) { c.TransitPeer = "8.8.8.8" }, func(c *Config) { c.TransitPeer = "10.231.0.8" }, func(c *Config) { c.TransitAddress = "10.231.0.0" },
		func(c *Config) { c.Domain = "mesh.example.com\n" }, func(c *Config) { c.Hostname = "--reset" }, func(c *Config) { c.LoginServer = "http://control.example.com" }, func(c *Config) { c.LoginServer = "https://user:secret@control.example.com" }, func(c *Config) { c.AuthKeyFile = "/etc/shadow" },
	} {
		c := fixture()
		change(&c)
		if c.validate() == nil {
			t.Errorf("accepted unsafe config: %+v", c)
		}
	}
}
func query(name string, kind uint16) []byte {
	q := make([]byte, 12)
	q[0] = 17
	q[2] = 1
	q[5] = 1
	for _, s := range strings.Split(name, ".") {
		q = append(q, byte(len(s)))
		q = append(q, s...)
	}
	q = append(q, 0, byte(kind>>8), byte(kind), 0, 1)
	return q
}
func TestDNSBoundary(t *testing.T) {
	for _, name := range []string{"example.org", "notmesh.example.com", "mesh.example.com.evil.org"} {
		r := resolve(query(name, 1), "127.0.0.1:1", "mesh.example.com", "udp")
		if r[3]&15 != 5 {
			t.Fatal("external query was not refused")
		}
	}
	for _, name := range []string{"mesh.example.com", "server.mesh.example.com"} {
		r := resolve(query(name, 28), "127.0.0.1:1", "mesh.example.com", "udp")
		if r[3]&15 != 0 || binary.BigEndian.Uint16(r[6:8]) != 0 {
			t.Fatal("AAAA must be NODATA")
		}
	}
	q := query("server.mesh.example.com", 1)
	q[12] = 0xc0
	if resolve(q, "127.0.0.1:1", "mesh.example.com", "udp") != nil {
		t.Fatal("compression accepted")
	}
	q = query("server.mesh.example.com", 1)
	q[5] = 2
	if resolve(q, "127.0.0.1:1", "mesh.example.com", "udp") != nil {
		t.Fatal("multiple questions accepted")
	}
	q = query("server.mesh.example.com", 255)
	if resolve(q, "127.0.0.1:1", "mesh.example.com", "udp")[3]&15 != 5 {
		t.Fatal("ANY accepted")
	}
}
func TestDNSUDPAndTCP(t *testing.T) {
	u, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	tcp, e := net.Listen("tcp4", u.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	respond := func(q []byte) []byte {
		_, _, end, e := question(q)
		if e != nil {
			return nil
		}
		r := answer(q, end, 0)
		r[7] = 1
		r = append(r, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 100, 80, 0, 2)
		return r
	}
	go func() {
		for {
			b := make([]byte, 4096)
			n, p, e := u.ReadFrom(b)
			if e != nil {
				return
			}
			u.WriteTo(respond(b[:n]), p)
		}
	}()
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				var sz [2]byte
				io.ReadFull(c, sz[:])
				b := make([]byte, binary.BigEndian.Uint16(sz[:]))
				io.ReadFull(c, b)
				r := respond(b)
				binary.BigEndian.PutUint16(sz[:], uint16(len(r)))
				c.Write(append(sz[:], r...))
			}()
		}
	}()
	// Reserve the front port; the service opens both transports on it.
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	front := l.Addr().String()
	l.Close()
	d, e := startDNS(context.Background(), front, u.LocalAddr().String(), "mesh.example.com")
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	for _, network := range []string{"udp", "tcp"} {
		q := query("server.mesh.example.com", 1)
		r := resolve(q, front, "mesh.example.com", network)
		if len(r) < 4 || string(r[len(r)-4:]) != string([]byte{100, 80, 0, 2}) {
			t.Fatalf("%s forwarding failed: %v", network, r)
		}
	}
	d.Close()
	time.Sleep(10 * time.Millisecond)
	if c, e := net.DialTimeout("tcp", front, 100*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("DNS listener survived shutdown")
	}
}
func TestHostExecutionRefused(t *testing.T) {
	if e := run(fixture()); e == nil {
		t.Fatal("ordinary process could mutate host namespace")
	}
}
func FuzzQuestion(f *testing.F) {
	f.Add(query("server.mesh.example.com", 1))
	f.Add([]byte{0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, end, e := question(b)
		if e == nil {
			r := answer(b, end, 5)
			if len(r) < 17 {
				t.Fatal("invalid response")
			}
		}
	})
}
