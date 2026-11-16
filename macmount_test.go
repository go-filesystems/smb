//go:build macmount

package smb_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	fssmb "github.com/go-filesystems/smb"
)

// The macOS client by hand: `mount_smbfs`, which offers 0x0311 among its
// dialects, mounting a share of this server on a high port, and the server
// reporting what the client NEGOTIATED. It is behind a build tag because it
// mounts a filesystem on the machine it runs on:
//
//	go test -tags macmount -run TestMacMount -v ./...
//
// macShareOptions are the options the share is exported with:
// SMB_ENCRYPT=share makes the share require encryption (RequireEncryption), and
// SMB_ENCRYPT=server makes the whole server require it (Server.EncryptData).
func macShareOptions() []fssmb.ShareOption {
	if os.Getenv("SMB_ENCRYPT") == "share" {
		return []fssmb.ShareOption{fssmb.RequireEncryption()}
	}
	return nil
}

func TestMacMount(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("mount_smbfs is macOS's")
	}
	mem := newMemFS(true)
	body := bytes.Repeat([]byte("go-filesystems/smb "), 40000) // 760 kB: several large reads
	if err := mem.WriteFile("/greeting.txt", body, 0o644); err != nil {
		t.Fatal(err)
	}

	var negotiated lockedBuffer
	srv := fssmb.New()
	srv.Logger = slog.New(slog.NewTextHandler(&negotiated, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv.AddUser("alice", "hunter2")
	srv.EncryptData = os.Getenv("SMB_ENCRYPT") == "server"
	// SMB_REQUIRE_SIGNING=1: the server is the one that insists (RequireSigning).
	srv.RequireSigning = os.Getenv("SMB_REQUIRE_SIGNING") != ""
	if err := srv.Share("disk", mem, macShareOptions()...); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	mnt := filepath.Join(t.TempDir(), "mnt")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	url := fmt.Sprintf("//alice:hunter2@127.0.0.1:%d/disk", port)
	if out, err := exec.Command("mount_smbfs", url, mnt).CombinedOutput(); err != nil {
		t.Fatalf("mount_smbfs: %v\n%s\nthe server logged:\n%s", err, out, negotiated.String())
	}
	defer exec.Command("umount", mnt).Run()

	got, err := os.ReadFile(filepath.Join(mnt, "greeting.txt"))
	if err != nil {
		t.Fatalf("reading through the mount: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("read %d bytes through the mount, want %d", len(got), len(body))
	}
	if err := os.WriteFile(filepath.Join(mnt, "written.txt"), []byte("through the mount"), 0o644); err != nil {
		t.Errorf("writing through the mount: %v", err)
	}
	t.Logf("macOS negotiated, as the server saw it:\n%s", strings.TrimSpace(negotiated.String()))
	if os.Getenv("SMB_REQUIRE_SIGNING") != "" && !strings.Contains(negotiated.String(), "signing_required=true") {
		t.Error("the server requires signing and the session does not record it")
	}
	if os.Getenv("SMB_ENCRYPT") != "" && !strings.Contains(negotiated.String(), "smb first encrypted request") {
		t.Error("encryption was required, and no request arrived encrypted")
	}
}
