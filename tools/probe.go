// Disposable integration probe. Standard library only; no runtime credentials.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func run() error {
	if len(os.Args) == 4 && os.Args[1] == "--enrollment-fixture" {
		return enrollmentFixture(os.Args[2], os.Args[3])
	}
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: probe SOCKS_ADDRESS TARGET_OR_CHECK [PORT]")
	}
	c, err := net.DialTimeout("tcp", os.Args[1], 4*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(c, reply); err != nil {
		return err
	}
	if reply[0] != 5 || reply[1] != 0 {
		return fmt.Errorf("SOCKS handshake failed")
	}
	if os.Args[2] == "--check" {
		return json.NewEncoder(os.Stdout).Encode(map[string]bool{"socks_healthy": true})
	}
	if len(os.Args) != 4 {
		return fmt.Errorf("destination port required")
	}
	port, err := strconv.Atoi(os.Args[3])
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port")
	}
	name := []byte(os.Args[2])
	if len(name) > 255 {
		return fmt.Errorf("invalid hostname")
	}
	request := append([]byte{5, 1, 0, 3, byte(len(name))}, name...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err = c.Write(request); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err = io.ReadFull(c, head); err != nil {
		return err
	}
	if head[1] != 0 {
		return fmt.Errorf("SOCKS destination rejected (%d)", head[1])
	}
	length := 0
	switch head[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		b := make([]byte, 1)
		if _, err = io.ReadFull(c, b); err != nil {
			return err
		}
		length = int(b[0])
	default:
		return fmt.Errorf("invalid SOCKS reply address")
	}
	if _, err = io.CopyN(io.Discard, c, int64(length+2)); err != nil {
		return err
	}
	req, err := http.NewRequest("GET", "http://"+net.JoinHostPort(os.Args[2], os.Args[3])+"/", nil)
	if err != nil {
		return err
	}
	req.Close = true
	if err = req.Write(c); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": response.StatusCode, "body": string(body)})
}

// Disposable HTTP upstream for presentation tests. It requires the same
// cookie/form field binding as the controller; no live identity or state is used.
func enrollmentFixture(address, root string) error {
	mux := http.NewServeMux()
	plain := func(w http.ResponseWriter, status int, message string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		io.WriteString(w, message)
	}
	file := func(w http.ResponseWriter, name string) {
		body, err := os.ReadFile(filepath.Join(root, name+".html"))
		if err != nil {
			plain(w, 500, "UNTRUSTED fixture failure")
			return
		}
		plain(w, 200, string(body))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register/start":
			http.SetCookie(w, &http.Cookie{Name: "state", Value: "test", Path: "/", HttpOnly: true})
			http.Redirect(w, r, "/oidc/callback", 302)
		case "/oidc/callback":
			http.SetCookie(w, &http.Cookie{Name: "headscale_register_confirm", Value: "FIXTURE-CSRF", Path: "/register/confirm/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
			http.Redirect(w, r, "/register/confirm/test", 303)
		case "/register/confirm/test":
			cookie, err := r.Cookie("headscale_register_confirm")
			if err != nil || cookie.Value != "FIXTURE-CSRF" {
				plain(w, 403, "UNTRUSTED missing csrf cookie")
				return
			}
			if r.Method == "GET" {
				file(w, "confirm")
				return
			}
			if r.Method != "POST" {
				plain(w, 405, "UNTRUSTED method")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			if r.ParseForm() != nil || r.PostFormValue("headscale_register_confirm") != cookie.Value {
				plain(w, 403, "UNTRUSTED csrf mismatch")
				return
			}
			file(w, "registered")
		case "/api/v1/node":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			io.WriteString(w, `{"message":"UNTRUSTED protocol body"}`)
		case "/ts2021":
			plain(w, 400, "UNTRUSTED protocol body")
		case "/derp":
			plain(w, 503, "UNTRUSTED protocol body")
		default:
			if strings.HasPrefix(r.URL.Path, "/register/status/") {
				status, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/register/status/"))
				if err == nil && status >= 400 && status <= 599 {
					plain(w, status, "UNTRUSTED upstream auth body")
					return
				}
			}
			for _, kind := range []string{"registered", "reauthenticated", "ssh"} {
				if r.URL.Path == "/auth/success/"+kind {
					file(w, kind)
					return
				}
			}
			plain(w, 404, "UNTRUSTED upstream auth body")
		}
	})
	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	return server.ListenAndServe()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
