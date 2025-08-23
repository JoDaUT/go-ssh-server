// Package main
// utils functions in this file are based on https://github.com/gliderlabs/ssh/blob/master/util.go
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
)

// parseString parses an ssh binary encrypted string
// See https://datatracker.ietf.org/doc/html/rfc4251#section-5
// Ssh strings are stored as a uint32 containing its length
// (number of bytes that follow) and zero (= empty string) or more
// bytes that are the value of the string.  Terminating null
// characters are not used.
func parseString(in []byte) (out string, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = string(in[4 : 4+length]) // Extract string
	rest = in[4+length:]           // Remaining bytes
	ok = true
	return
}

// parseUint32 parses the in[0:4] as uint32
func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

// uint32ToBytes parses a uint32 into b[0:4]
func uint32ToBytes(status uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(status))
	return b
}

func readAuthorizedKeysFile(filepath string) (map[string]bool, error) {
	authorizedKeysBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to load authorized_keys, err: %w", err)
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return nil, fmt.Errorf("public key parsing: %w", err)
		}
		authorizedKeysMap[ssh.FingerprintSHA256(pubKey)] = true
		authorizedKeysBytes = rest
	}
	return authorizedKeysMap, nil
}

func getPrivateKeySigner(privateKeyFile string) (ssh.Signer, error) {
	privateBytes, err := os.ReadFile(privateKeyFile)

	if err != nil {
		return nil, fmt.Errorf("error reading private key: %s", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)

	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %s", err)
	}

	return private, nil
}

func parsePtyRequest(payload []byte) (ptyReq, bool) {
	term, rest, ok := parseString(payload)
	if !ok {
		return ptyReq{}, false
	}
	width32, rest, ok := parseUint32(rest)
	if !ok {
		return ptyReq{}, false
	}
	height32, _, ok := parseUint32(rest)
	if !ok {
		return ptyReq{}, false
	}
	pty := ptyReq{
		Term: term,
		Window: window{
			Width:  int(width32),
			Height: int(height32),
		},
	}
	return pty, true
}

func loadUsersMap(users []string) (map[string]userInfo, error) {
	userDetails, err := loadUserInfo(users)
	if err != nil {
		return nil, fmt.Errorf("could not load details for authorized users")
	}
	userInfo := make(map[string]userInfo, len(users))
	for _, user := range userDetails {
		userInfo[user.name] = user
	}
	return userInfo, nil
}

func loadUserInfo(users []string) ([]userInfo, error) {
	usersData := []userInfo{}

	if len(users) == 0 {
		return usersData, nil
	}

	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("could not open /etc/passwd file")
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		username := parts[0]
		if !slices.Contains(users, username) {
			continue
		}
		uid := parts[2]
		gid := parts[3]
		home := parts[5]
		shell := parts[6]

		user := userInfo{
			name:  username,
			uid:   uid,
			gid:   gid,
			home:  home,
			shell: shell,
		}

		usersData = append(usersData, user)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning error: %s", err)
	}

	return usersData, nil
}

type userInfo struct {
	name  string
	uid   string
	gid   string
	home  string
	shell string
}

type window struct {
	Width  int
	Height int
}

type ptyReq struct {
	Term   string
	Window window
}
