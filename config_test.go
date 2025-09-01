package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadCfg(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		want    Cfg
		wantErr bool
	}{
		{
			name:    "unexisting config file",
			file:    "unexisting-file.yaml",
			wantErr: true,
		},
		{
			name: "valid config",
			file: "testdata/config.test.yaml",
			want: Cfg{
				Port:              "8001",
				Interface:         "0.0.0.0",
				AuthorizedKeyFile: "testdata/authorized_keys",
				PrivateKeyFile:    "testdata/fake_server_key",
				AuthorizedUsers:   []string{"test"},
				PasswdFile:        "testdata/passwd.txt",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := LoadCfg(tt.file)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("LoadCfg() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("LoadCfg() succeeded unexpectedly")
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
