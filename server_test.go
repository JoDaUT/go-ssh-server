package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

var (
	fakePubKey1        = []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKQaUh3kI70OtSg1Lti5OrjZwoLMIHPvwRTpSOL/rUvd fake@email.com")
	fakePubKey2        = []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDZBjEddpaQjKMuIaj3Z1tNemcuyG3j1kQUjgzEb/Uoa fakeclientkey@email.com")
	unauthorizedPubKey = []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGgNTcVhqL0BnjVW0kwWG+XyGveY/QyO34pKSm67M8j6 fake2@email.com")
	validUser          = "myuser"
)

func TestPubKeyCallback(t *testing.T) {
	authorizedKeys, err := readAuthorizedKeysFile("testdata/authorized_keys")
	if err != nil {
		t.Fatal("error reading authorized keys", err)
	}

	pubKey1, _, _, _, err := ssh.ParseAuthorizedKey(fakePubKey1)
	if err != nil {
		t.Fatal("error reading public key", err)
	}
	unauthorizedKey, _, _, _, err := ssh.ParseAuthorizedKey(unauthorizedPubKey)
	if err != nil {
		t.Fatal("error reading public key, err")
	}

	tests := []struct {
		name            string
		user            string
		key             ssh.PublicKey
		authorizedKeys  map[string]bool
		authorizedUsers []string
		wantErr         assert.ErrorAssertionFunc
		want            *ssh.Permissions
	}{
		{
			name:            "valid auth key",
			authorizedKeys:  authorizedKeys,
			key:             pubKey1,
			user:            validUser,
			authorizedUsers: []string{validUser},
			wantErr:         assert.NoError,
			want: &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey": string(pubKey1.Marshal()),
				},
			},
		},
		{
			name:            "auth key not present in auth key map",
			authorizedKeys:  authorizedKeys,
			key:             unauthorizedKey,
			wantErr:         assert.Error,
			user:            validUser,
			authorizedUsers: []string{validUser},
		},
		{
			name:            "user not authorized",
			authorizedKeys:  authorizedKeys,
			key:             unauthorizedKey,
			wantErr:         assert.Error,
			user:            "invalid-user",
			authorizedUsers: []string{validUser},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sshServer := NewSshServer(nil)
			got, err := sshServer.pubKeyCallback(tt.user, tt.key, tt.authorizedKeys, tt.authorizedUsers)
			if !tt.wantErr(t, err) {
				t.Fail()
				return
			}

			if tt.want == nil {
				return
			}
			assert.NotNil(t, got)
			assert.Equal(t, string(tt.key.Marshal()), got.Extensions["pubkey"])
		})
	}
}
