package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func TestReadAuthorizedKeysFile(t *testing.T) {
	pubKey1, _, _, _, err := ssh.ParseAuthorizedKey(fakePubKey1)
	if err != nil {
		t.Fatal("error parsing public key", err)
	}
	pubKey2, _, _, _, err := ssh.ParseAuthorizedKey(fakePubKey2)
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
				ssh.FingerprintSHA256(pubKey1): true,
				ssh.FingerprintSHA256(pubKey2): true,
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
