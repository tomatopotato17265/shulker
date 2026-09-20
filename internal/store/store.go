package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	dirName  = "shulker"
	fileName = "auth.json"
)

type DeviceToken struct {
	ID            string         `json:"id"`
	PrivateKey    string         `json:"private_key"`
	X             string         `json:"x"`
	Y             string         `json:"y"`
	IssueInstant  time.Time      `json:"issue_instant"`
	NotAfter      time.Time      `json:"not_after"`
	Token         string         `json:"token"`
	DisplayClaims map[string]any `json:"display_claims,omitempty"`
}

type Credentials struct {
	ProfileID    string    `json:"profile_id"`
	ProfileName  string    `json:"profile_name"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Expires      time.Time `json:"expires"`
	Active       bool      `json:"active"`
}

type data struct {
	Device *DeviceToken  `json:"device,omitempty"`
	Users  []Credentials `json:"users"`
}

type Store struct {
	path string
	mu   sync.Mutex
}

func New(dir string) *Store {
	return &Store{path: filepath.Join(dir, fileName)}
}

func Default() (*Store, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("locating config directory: %w", err)
	}
	return New(filepath.Join(base, dirName)), nil
}

func (s *Store) Device() (*DeviceToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, err := s.load()
	if err != nil {
		return nil, err
	}
	return d.Device, nil
}

func (s *Store) SetDevice(device DeviceToken) error {
	return s.update(func(d *data) {
		d.Device = &device
	})
}

func (s *Store) Users() ([]Credentials, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, err := s.load()
	if err != nil {
		return nil, err
	}
	return d.Users, nil
}

func (s *Store) DefaultUser() (*Credentials, error) {
	users, err := s.Users()
	if err != nil {
		return nil, err
	}
	for i := range users {
		if users[i].Active {
			return &users[i], nil
		}
	}
	return nil, nil
}

func (s *Store) UpsertUser(user Credentials) error {
	user.Active = true
	return s.update(func(d *data) {
		users := d.Users[:0:0]
		for _, u := range d.Users {
			if u.ProfileID == user.ProfileID {
				continue
			}
			u.Active = false
			users = append(users, u)
		}
		d.Users = append(users, user)
	})
}

func (s *Store) RemoveUser(profileID string) error {
	return s.update(func(d *data) {
		users := d.Users[:0:0]
		hadActive, hasActive := false, false
		for _, u := range d.Users {
			if u.ProfileID == profileID {
				hadActive = u.Active
				continue
			}
			hasActive = hasActive || u.Active
			users = append(users, u)
		}
		if hadActive && !hasActive && len(users) > 0 {
			users[0].Active = true
		}
		d.Users = users
	})
}

func (s *Store) update(fn func(*data)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, err := s.load()
	if err != nil {
		return err
	}
	fn(&d)
	return s.save(d)
}

func (s *Store) load() (data, error) {
	var d data
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return d, fmt.Errorf("reading %s: %w", s.path, err)
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, fmt.Errorf("parsing %s: %w", s.path, err)
	}
	return d, nil
}

func (s *Store) save(d data) error {
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, fileName+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
