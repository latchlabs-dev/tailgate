package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Deliberately accept only normal, single-question queries. Reject compressed
// query names and other opcodes instead of maintaining a recursive DNS parser.
func question(b []byte) (name string, kind uint16, end int, err error) {
	bad := errors.New("malformed DNS question")
	if len(b) < 17 || len(b) > 4096 || b[2]&0xf8 != 0 || b[3]&0x0f != 0 || binary.BigEndian.Uint16(b[4:6]) != 1 || binary.BigEndian.Uint32(b[6:10]) != 0 {
		return "", 0, 0, bad
	}
	i := 12
	var labels []string
	for {
		if i >= len(b) {
			return "", 0, 0, bad
		}
		n := int(b[i])
		i++
		if n == 0 {
			break
		}
		if n > 63 || i+n > len(b) {
			return "", 0, 0, bad
		}
		part := strings.ToLower(string(b[i : i+n]))
		if !label.MatchString(part) {
			return "", 0, 0, bad
		}
		labels = append(labels, part)
		i += n
	}
	name = strings.Join(labels, ".")
	if len(name) > 253 || i+4 > len(b) || binary.BigEndian.Uint16(b[i+2:i+4]) != 1 {
		return "", 0, 0, bad
	}
	return name, binary.BigEndian.Uint16(b[i : i+2]), i + 4, nil
}

func answer(q []byte, end int, rcode byte) []byte {
	r := append([]byte(nil), q[:end]...)
	r[2] = (q[2] & 1) | 0x80
	r[3] = 0x80 | rcode
	for i := 6; i < 12; i++ {
		r[i] = 0
	}
	return r
}

func resolve(q []byte, upstream, domain, network string) []byte {
	name, kind, end, err := question(q)
	if err != nil {
		return nil
	}
	if name != domain && !strings.HasSuffix(name, "."+domain) {
		return answer(q, end, 5)
	}
	// IPv6 is intentionally unavailable during this migration. NODATA prevents
	// clients from selecting an unreachable Tailgate AAAA address.
	if kind == 28 {
		return answer(q, end, 0)
	}
	if kind != 1 {
		return answer(q, end, 5)
	}
	c, err := net.DialTimeout(network, upstream, 2*time.Second)
	if err != nil {
		return answer(q, end, 2)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	var response []byte
	if network == "tcp" {
		frame := make([]byte, 2+len(q))
		binary.BigEndian.PutUint16(frame, uint16(len(q)))
		copy(frame[2:], q)
		if _, err = c.Write(frame); err == nil {
			var size [2]byte
			if _, err = io.ReadFull(c, size[:]); err == nil {
				n := int(binary.BigEndian.Uint16(size[:]))
				if n < 12 || n > 4096 {
					err = errors.New("invalid frame")
				} else {
					response = make([]byte, n)
					_, err = io.ReadFull(c, response)
				}
			}
		}
	} else {
		if _, err = c.Write(q); err == nil {
			response = make([]byte, 4097)
			var n int
			n, err = c.Read(response)
			response = response[:n]
		}
	}
	if err != nil || len(response) < end || len(response) > 4096 || !bytes.Equal(q[:2], response[:2]) || response[2]&0x80 == 0 || !bytes.Equal(q[4:6], response[4:6]) || !bytes.Equal(q[12:end], response[12:end]) {
		return answer(q, end, 2)
	}
	// Legacy UDP requests have a 512-byte limit; EDNS requests are bounded to
	// 1232 bytes. A truncated reply causes the client's normal TCP retry.
	limit := 512
	if binary.BigEndian.Uint16(q[10:12]) != 0 {
		limit = 1232
	}
	if network == "udp" && len(response) > limit {
		r := answer(q, end, 0)
		r[2] |= 2
		return r
	}
	return response
}

type dnsServer struct {
	udp    net.PacketConn
	tcp    net.Listener
	once   sync.Once
	cancel context.CancelFunc
}

func (d *dnsServer) Close() { d.once.Do(func() { d.cancel(); _ = d.udp.Close(); _ = d.tcp.Close() }) }

func startDNS(parent context.Context, listen, upstream, domain string) (*dnsServer, error) {
	u, err := net.ListenPacket("udp4", listen)
	if err != nil {
		return nil, err
	}
	t, err := net.Listen("tcp4", listen)
	if err != nil {
		u.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	d := &dnsServer{udp: u, tcp: t, cancel: cancel}
	// Bound concurrency, memory, upstream work and slow TCP sessions.
	slots := make(chan struct{}, 128)
	go func() { <-ctx.Done(); d.Close() }()
	go func() {
		for {
			buf := make([]byte, 4097)
			n, peer, e := u.ReadFrom(buf)
			if e != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				go func(q []byte, p net.Addr) {
					defer func() { <-slots }()
					r := resolve(q, upstream, domain, "udp")
					if r != nil {
						_, _ = u.WriteTo(r, p)
					}
				}(buf[:n], peer)
			default:
			}
		}
	}()
	go func() {
		for {
			c, e := t.Accept()
			if e != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				go func() {
					defer func() { c.Close(); <-slots }()
					for {
						_ = c.SetDeadline(time.Now().Add(5 * time.Second))
						var size [2]byte
						if _, e := io.ReadFull(c, size[:]); e != nil {
							return
						}
						n := int(binary.BigEndian.Uint16(size[:]))
						if n < 17 || n > 4096 {
							return
						}
						q := make([]byte, n)
						if _, e := io.ReadFull(c, q); e != nil {
							return
						}
						r := resolve(q, upstream, domain, "tcp")
						if r == nil {
							return
						}
						binary.BigEndian.PutUint16(size[:], uint16(len(r)))
						frame := append(size[:], r...)
						if _, e := c.Write(frame); e != nil {
							return
						}
						select {
						case <-ctx.Done():
							return
						default:
						}
					}
				}()
			default:
				c.Close()
			}
		}
	}()
	return d, nil
}
