package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type Config struct {
	Server string `json:"server"`
	Token  string `json:"token"`
}

func ConfigDir() (string, error) {
	if d := os.Getenv("BNAT_CONFIG_DIR"); d != "" {
		return d, nil
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "bnat"), nil
}

// LoadConfig reads the saved config; BNAT_SERVER / BNAT_TOKEN override it.
func LoadConfig() (Config, error) {
	var c Config
	dir, err := ConfigDir()
	if err != nil {
		return c, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return c, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &c); err != nil {
			return c, err
		}
	}
	if v := os.Getenv("BNAT_SERVER"); v != "" {
		c.Server = v
	}
	if v := os.Getenv("BNAT_TOKEN"); v != "" {
		c.Token = v
	}
	if c.Server == "" || c.Token == "" {
		return c, errors.New("not logged in: run `bnat login https://bnat.example.com <CODE>` (code from admin panel → Clients)")
	}
	return c, nil
}

func SaveConfig(c Config) (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	p := filepath.Join(dir, "config.json")
	return p, os.WriteFile(p, b, 0o600)
}
