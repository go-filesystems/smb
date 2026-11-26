package smb_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-filesystems/smb/client"
)

// Samba is the reference server: a client that requires encryption must get an
// encrypted session from it under both `server smb encrypt` settings that
// allow it. The test needs docker and the network (it installs Samba into an
// Alpine 3.22 image, Samba 4.22), so it runs only when SMB_SAMBA_INTEROP=1.
func TestSambaEncryption(t *testing.T) {
	if os.Getenv("SMB_SAMBA_INTEROP") != "1" {
		t.Skip("set SMB_SAMBA_INTEROP=1 (needs docker and the network)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	for _, mode := range []string{"required", "desired"} {
		t.Run(mode, func(t *testing.T) {
			conf := "[global]\n" +
				"  server min protocol = SMB3\n" +
				"  server smb encrypt = " + mode + "\n" +
				"  server signing = mandatory\n" +
				"  security = user\n" +
				"  map to guest = never\n" +
				"[disk]\n  path = /srv\n  read only = no\n"
			script := "apk add --no-cache samba >/dev/null && " +
				"mkdir -p /srv && echo hello > /srv/hello.txt && " +
				"adduser -D alice && printf 'hunter2\\nhunter2\\n' | smbpasswd -s -a alice >/dev/null && " +
				"printf '%s' \"$SMBCONF\" > /etc/samba/smb.conf && exec smbd -F --no-process-group --debug-stdout"
			run := exec.Command("docker", "run", "-d", "--rm", "-e", "SMBCONF="+conf,
				"-p", "127.0.0.1::445", "alpine:3.22", "sh", "-c", script)
			out, err := run.CombinedOutput()
			if err != nil {
				t.Fatalf("docker run: %v\n%s", err, out)
			}
			id := strings.TrimSpace(string(out))
			t.Cleanup(func() { exec.Command("docker", "rm", "-f", id).Run() })
			pout, err := exec.Command("docker", "port", id, "445/tcp").Output()
			if err != nil {
				t.Fatalf("docker port: %v", err)
			}
			addr := strings.TrimSpace(strings.SplitN(string(pout), "\n", 2)[0])
			tg, err := client.ParseUNC("//" + addr + "/disk")
			if err != nil {
				t.Fatal(err)
			}
			auth := client.NTLM{Credentials: client.Credentials{User: "alice", Password: "hunter2"}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			deadline := time.Now().Add(120 * time.Second)
			var s *client.Session
			for {
				s, err = client.Dial(ctx, tg, client.Options{Auth: auth, ConnectTimeout: 10 * time.Second})
				if err == nil || time.Now().After(deadline) {
					break
				}
				time.Sleep(2 * time.Second) // apk is still installing, or smbd is starting
			}
			if err != nil {
				t.Fatalf("Dial against Samba (server smb encrypt = %s): %v", mode, err)
			}
			defer s.Close()
			if !s.Encrypted() {
				t.Fatalf("Samba (%s): the session is not encrypted", mode)
			}
			sh, err := s.Mount(tg.Share)
			if err != nil {
				t.Fatal(err)
			}
			defer sh.Close()
			ents, err := sh.ReadDir("")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, e := range ents {
				found = found || e.Name == "hello.txt"
			}
			if !found {
				t.Fatalf("hello.txt not listed: %v", ents)
			}
		})
	}
}
