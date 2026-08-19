package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const version = "0.1.0"

type config struct {
	Server, DeviceID, Credential string
}

type observation struct {
	IdempotencyKey string         `json:"idempotency_key"`
	SchemaVersion  string         `json:"schema_version"`
	ObservedAt     time.Time      `json:"observed_at"`
	Facts          map[string]any `json:"facts"`
}

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: watchtower-agent <enroll|collect|check-in|ui|uninstall>"))
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		err = enroll(os.Args[2:])
	case "collect":
		err = json.NewEncoder(os.Stdout).Encode(collect())
	case "check-in":
		err = checkIn(collect())
	case "ui":
		err = serveUI(os.Args[2:])
	case "uninstall":
		err = uninstall(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "watchtower-agent:", err); os.Exit(1) }

func configPath() (string, error) {
	directory, err := os.UserConfigDir()
	return filepath.Join(directory, "watchtower-agent", "credential.json"), err
}

func loadConfig() (config, error) {
	path, err := configPath()
	if err != nil {
		return config{}, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	var value config
	err = json.Unmarshal(content, &value)
	return value, err
}

func saveConfig(value config) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	content, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, content, 0600)
}

func enroll(arguments []string) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	server := flags.String("server", "", "Watchtower API base URL")
	token := flags.String("token", "", "one-time enrollment token")
	tokenFile := flags.String("token-file", "", "protected token file, or - for stdin")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	secret := *token
	if *tokenFile != "" {
		var content []byte
		var err error
		if *tokenFile == "-" {
			content, err = io.ReadAll(os.Stdin)
		} else {
			content, err = os.ReadFile(*tokenFile)
		}
		if err != nil {
			return err
		}
		secret = strings.TrimSpace(string(content))
	}
	if *server == "" || secret == "" {
		return errors.New("--server and a token source are required")
	}
	hostname, _ := os.Hostname()
	payload := map[string]string{"token": secret, "platform": platform(), "hostname": hostname, "public_key": "bootstrap:" + randomID(), "agent_version": version}
	var response struct {
		DeviceID   string `json:"device_id"`
		Credential string `json:"credential"`
	}
	if err := postJSON(strings.TrimRight(*server, "/")+"/v1/agent-enrollments:exchange", payload, "", &response); err != nil {
		return err
	}
	return saveConfig(config{Server: strings.TrimRight(*server, "/"), DeviceID: response.DeviceID, Credential: response.Credential})
}

func platform() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	return runtime.GOOS
}

func collect() observation {
	hostname, _ := os.Hostname()
	return observation{IdempotencyKey: randomID(), SchemaVersion: "v1", ObservedAt: time.Now().UTC(), Facts: map[string]any{
		"os":     map[string]string{"family": platform(), "architecture": runtime.GOARCH},
		"device": map[string]string{"hostname": hostname}, "collector": map[string]string{"version": version},
	}}
}

func checkIn(value observation) error {
	settings, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load credential: %w", err)
	}
	return postJSON(fmt.Sprintf("%s/v1/agents/%s/check-ins", settings.Server, settings.DeviceID), value, settings.Credential, nil)
}

func postJSON(url string, payload any, credential string, output any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("server returned %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	if output != nil {
		return json.NewDecoder(response.Body).Decode(output)
	}
	return nil
}

func randomID() string {
	value := make([]byte, 16)
	_, _ = rand.Read(value)
	value[6], value[8] = (value[6]&0x0f)|0x40, (value[8]&0x3f)|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

func serveUI(arguments []string) error {
	flags := flag.NewFlagSet("ui", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:17654", "loopback listen address")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if !strings.HasPrefix(*listen, "127.0.0.1:") && !strings.HasPrefix(*listen, "[::1]:") {
		return errors.New("status UI must bind to loopback")
	}
	http.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) {
		settings, err := loadConfig()
		state, device := "Not enrolled", "—"
		if err == nil {
			state, device = "Enrolled", settings.DeviceID
		}
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(writer, "<!doctype html><title>Watchtower agent</title><style>body{font:16px system-ui;max-width:720px;margin:60px auto;padding:20px;color:#172033}h1{color:#062247}dl{display:grid;grid-template-columns:140px 1fr;gap:12px}</style><h1>Watchtower endpoint collector</h1><p>This sensor collects only allow-listed security posture facts. It has no remote shell.</p><dl><dt>Status</dt><dd>%s</dd><dt>Device ID</dt><dd>%s</dd><dt>Platform</dt><dd>%s/%s</dd><dt>Version</dt><dd>%s</dd></dl>", state, device, platform(), runtime.GOARCH, version)
	})
	fmt.Println("Watchtower status UI: http://" + *listen)
	return http.ListenAndServe(*listen, nil)
}

func uninstall(arguments []string) error {
	flags := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	notify := flags.Bool("notify", false, "attempt final authenticated check-in")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *notify {
		value := collect()
		value.Facts["lifecycle"] = map[string]string{"event": "uninstall_started"}
		_ = checkIn(value)
	}
	path, err := configPath()
	if err != nil {
		return err
	}
	if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
