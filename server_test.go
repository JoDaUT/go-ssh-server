package main

import (
	"testing"

	"github.com/JoDaUT/go-ssh-server/mock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

var (
	fakePublicKey1 = []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOmSeOS8D8eZOcxtjstJC19TQcduSAvR71tyxmZvABWz fake@email.com")
	fakePublicKey2 = []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGgNTcVhqL0BnjVW0kwWG+XyGveY/QyO34pKSm67M8j6 fake2@email.com")
	fakePublicKey3 = []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDtbIIZ3BeytmG+zU7ssDPVzaRx8+mAdreK0oxTPFcfV fake2@email.com")
	connMetaData   = &mock.MockConnMetadata{
		UserCallbackFn: func() string {
			return "myuser"
		},
	}
)

func TestReadAuthorizedKeysFile(t *testing.T) {
	pubKey1, _, _, _, err := ssh.ParseAuthorizedKey(fakePublicKey1)
	if err != nil {
		t.Fatal("error parsing public key", err)
	}
	pubKey2, _, _, _, err := ssh.ParseAuthorizedKey(fakePublicKey2)
	if err != nil {
		t.Fatal("error parsing public key", err)
	}
	tests := []struct {
		name     string
		filepath string
		want     map[string]bool
		wantErr  bool
	}{
		{
			name:     "read unexisting file",
			filepath: "does-not-exist",
			wantErr:  true,
		},
		{
			name:     "file with multiple authorized keys",
			filepath: "testdata/authorized_keys",
			wantErr:  false,
			want: map[string]bool{
				string(pubKey1.Marshal()): true,
				string(pubKey2.Marshal()): true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := readAuthorizedKeysFile(tt.filepath)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("ReadAuthorizedKeysFile() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("ReadAuthorizedKeysFile() succeeded unexpectedly")
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestPubKeyCallback(t *testing.T) {
	authorizedKeys, err := readAuthorizedKeysFile("testdata/authorized_keys")
	if err != nil {
		t.Fatal("error reading authorized keys", err)
	}

	pubKey1, _, _, _, err := ssh.ParseAuthorizedKey(fakePublicKey1)
	if err != nil {
		t.Fatal("error reading public key", err)
	}
	unauthorizedKey, _, _, _, err := ssh.ParseAuthorizedKey(fakePublicKey3)
	if err != nil {
		t.Fatal("error reading public key, err")
	}

	tests := []struct {
		name            string
		conn            ssh.ConnMetadata
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
			conn:            connMetaData,
			authorizedUsers: []string{"myuser"},
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
			conn:            connMetaData,
			authorizedUsers: []string{"myuser"},
		},
		{
			name:           "user not authorized",
			authorizedKeys: authorizedKeys,
			key:            unauthorizedKey,
			wantErr:        assert.Error,
			conn: &mock.MockConnMetadata{
				UserCallbackFn: func() string {
					return "other-user"
				},
			},
			authorizedUsers: []string{"myuser"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pubKeyCallback(tt.conn, tt.key, tt.authorizedKeys, tt.authorizedUsers)
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
