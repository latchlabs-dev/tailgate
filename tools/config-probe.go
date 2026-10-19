// Disposable integration helper. Never use production state or credentials.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 5 {
		panic("expected origin, login file, gateway ID, allowed-users JSON or disabled")
	}
	origin := os.Args[1]
	u, err := url.Parse(origin)
	if err != nil {
		panic("invalid origin")
	}
	credential, err := os.ReadFile(os.Args[2])
	if err != nil {
		panic("missing disposable login")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	var cookie, csrf string
	request := func(path string, payload any) []byte {
		var body io.Reader
		method := "GET"
		if payload != nil {
			b, _ := json.Marshal(payload)
			body = bytes.NewReader(b)
			method = "POST"
		}
		req, _ := http.NewRequest(method, "http://127.0.0.1:18100"+path, body)
		req.Host = u.Host
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Cookie", cookie)
		resp, err := client.Do(req)
		if err != nil {
			panic("configuration API unreachable")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			panic(fmt.Sprintf("configuration API status %d", resp.StatusCode))
		}
		for _, c := range resp.Cookies() {
			cookie = c.Name + "=" + c.Value
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			panic("configuration API read failed")
		}
		return b
	}
	b := request("/api/login", map[string]string{"token": strings.TrimSpace(string(credential))})
	var login struct {
		CSRF string `json:"csrf"`
	}
	json.Unmarshal(b, &login)
	csrf = login.CSRF
	b = request("/api/bridge-config", nil)
	var state struct {
		Revision uint64 `json:"revision"`
	}
	json.Unmarshal(b, &state)
	var users []string
	enabled := os.Args[4] != "disabled"
	if enabled && json.Unmarshal([]byte(os.Args[4]), &users) != nil {
		panic("invalid disposable accounts")
	}
	b = request("/api/bridge-config", map[string]any{"id": os.Args[3], "revision": state.Revision, "enabled": enabled, "allowed_users": users})
	fmt.Println(string(b))
}
