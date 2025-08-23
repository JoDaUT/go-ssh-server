package main

import (
	"bytes"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

func setupClient(user string, addr string) (*ssh.Client, error) {
	privateKeySigner, err := getPrivateKeySigner("testdata/fake_client_key")
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(privateKeySigner),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //this is ok for testing
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func setupServer(cfg *Cfg) (*SshServer, error) {
	sshServer := NewSshServer(cfg)

	if err := sshServer.Init(); err != nil {
		return nil, err
	}

	if err := sshServer.Listen(); err != nil {
		return nil, err
	}

	go sshServer.Accept()

	return sshServer, nil
}

func loadTestConfig() (*Cfg, error) {
	cfg, err := LoadCfg("testdata/config.test.yaml")
	cfg.Port = "0"
	cfg.AuthorizedKeyFile = "testdata/authorized_keys"
	cfg.PrivateKeyFile = "testdata/fake_server_key"

	if err != nil {
		return nil, fmt.Errorf("could not load cfg file")
	}
	return &cfg, nil
}

func startInteractiveSession(client *ssh.Client) (*ssh.Session, *bytes.Buffer, *bytes.Buffer, io.WriteCloser, error) {
	var stdOutBuff bytes.Buffer
	var stdErrBuff bytes.Buffer
	session, err := client.NewSession()

	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("could no start session: %s", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("could no configure stdin: %s", err)
	}

	session.Stdout = &stdOutBuff
	session.Stderr = &stdErrBuff

	terminalModes := ssh.TerminalModes{
		ssh.ECHO: 0,
	}

	if err := session.RequestPty("xterm-256color", 720, 1280, terminalModes); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("could not configure pty: %s", err)
	}

	if err := session.Shell(); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("could not configure shell: %s", err)
	}

	return session, &stdOutBuff, &stdErrBuff, stdin, nil
}
