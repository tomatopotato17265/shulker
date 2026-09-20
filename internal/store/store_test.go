package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestEmptyStore(t *testing.T) {
	s := New(t.TempDir())

	if d, err := s.Device(); err != nil || d != nil {
		t.Fatalf("Device() = %v, %v; want nil, nil", d, err)
	}
	if u, err := s.Users(); err != nil || len(u) != 0 {
		t.Fatalf("Users() = %v, %v; want empty, nil", u, err)
	}
	if u, err := s.DefaultUser(); err != nil || u != nil {
		t.Fatalf("DefaultUser() = %v, %v; want nil, nil", u, err)
	}
}

func TestDeviceRoundTrip(t *testing.T) {
	s := New(t.TempDir())
	want := DeviceToken{
		ID:            "id",
		PrivateKey:    "pem",
		X:             "x",
		Y:             "y",
		IssueInstant:  time.Unix(1000, 0).UTC(),
		NotAfter:      time.Unix(2000, 0).UTC(),
		Token:         "tok",
		DisplayClaims: map[string]any{"xdi": map[string]any{"did": "d"}},
	}
	if err := s.SetDevice(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Device()
	if err != nil || got == nil {
		t.Fatalf("Device() = %v, %v", got, err)
	}
	if got.ID != want.ID || got.PrivateKey != want.PrivateKey || got.X != want.X ||
		got.Y != want.Y || got.Token != want.Token ||
		!got.IssueInstant.Equal(want.IssueInstant) || !got.NotAfter.Equal(want.NotAfter) ||
		got.DisplayClaims["xdi"] == nil {
		t.Fatalf("Device() = %+v; want %+v", got, want)
	}
}

func TestUpsertUserKeepsSingleActive(t *testing.T) {
	s := New(t.TempDir())

	if err := s.UpsertUser(Credentials{ProfileID: "a", ProfileName: "Alice"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertUser(Credentials{ProfileID: "b", ProfileName: "Bob"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertUser(Credentials{ProfileID: "a", ProfileName: "Alice2"}); err != nil {
		t.Fatal(err)
	}

	users, _ := s.Users()
	if len(users) != 2 {
		t.Fatalf("got %d users; want 2", len(users))
	}
	def, _ := s.DefaultUser()
	if def == nil || def.ProfileID != "a" || def.ProfileName != "Alice2" {
		t.Fatalf("DefaultUser() = %+v; want a/Alice2", def)
	}
	active := 0
	for _, u := range users {
		if u.Active {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("%d active users; want 1", active)
	}
}

func TestRemoveUserPromotesRemaining(t *testing.T) {
	s := New(t.TempDir())
	_ = s.UpsertUser(Credentials{ProfileID: "a"})
	_ = s.UpsertUser(Credentials{ProfileID: "b"})

	if err := s.RemoveUser("b"); err != nil {
		t.Fatal(err)
	}
	def, _ := s.DefaultUser()
	if def == nil || def.ProfileID != "a" {
		t.Fatalf("DefaultUser() = %+v; want a", def)
	}

	if err := s.RemoveUser("a"); err != nil {
		t.Fatal(err)
	}
	if def, _ := s.DefaultUser(); def != nil {
		t.Fatalf("DefaultUser() = %+v; want nil", def)
	}
}

func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	dir := filepath.Join(t.TempDir(), "nested")
	s := New(dir)
	if err := s.UpsertUser(Credentials{ProfileID: "a"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, fileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file mode = %o; want 600", perm)
	}
	di, _ := os.Stat(dir)
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Fatalf("dir mode = %o; want 700", perm)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("dir has %d entries; want 1", len(entries))
	}
}

func TestCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir).Users(); err == nil {
		t.Fatal("expected error for corrupt file")
	}
}
