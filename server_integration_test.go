package main

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

type errorResults struct {
	mu   sync.Mutex
	errs []error
}

func TestExecuteSingleCommand(t *testing.T) {
	cfg, err := loadTestConfig()
	if err != nil {
		t.Fatal()
	}
	server, err := setupServer(cfg)
	if err != nil {
		t.Fatal("could not start ssh server", err)
	}
	defer server.Close()

	addr := strings.Split(server.Addr().String(), ":")
	port := addr[len(addr)-1]

	client, err := setupClient(cfg.AuthorizedUsers[0], "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	session, err := client.NewSession()

	if err != nil {
		t.Fatal(err)
	}

	defer session.Close()

	output, err := session.CombinedOutput("echo \"result=$((2+2))\"")

	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, "result=4\n", string(output))
}

func TestStartInteractiveShell(t *testing.T) {
	cfg, err := loadTestConfig()
	if err != nil {
		t.Fatal()
	}
	server, err := setupServer(cfg)
	if err != nil {
		t.Fatal("could not start ssh server", err)
	}
	defer server.Close()

	addr := strings.Split(server.Addr().String(), ":")
	port := addr[len(addr)-1]

	client, err := setupClient(cfg.AuthorizedUsers[0], "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	session, stdout, stderr, stdin, err := startInteractiveSession(client)
	if err != nil {
		t.Fatal(err)
	}

	cmd := "echo \"result=$((2+2))\" && exit"
	expectedOutput := "result=4"
	fmt.Fprintln(stdin, cmd)

	if err := session.Wait(); err != nil {
		t.Error(fmt.Errorf("error waiting session: %s", err))
	}

	stdErrOutput := stderr.String()
	if len(stdErrOutput) != 0 {
		t.Error(fmt.Errorf("expected empty stderr, but found: %s", stdErrOutput))
	}

	stdoutOutput := stdout.String()
	assert.True(t, strings.Contains(stdoutOutput, expectedOutput))
}

func TestHandleConcurrentConnections(t *testing.T) {
	cfg, err := loadTestConfig()
	if err != nil {
		t.Fatal()
	}
	server, err := setupServer(cfg)
	if err != nil {
		t.Fatal("could not start ssh server", err)
	}
	defer server.Close()

	addr := strings.Split(server.Addr().String(), ":")
	port := addr[len(addr)-1]

	client, err := setupClient(cfg.AuthorizedUsers[0], "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var wg sync.WaitGroup
	clients := 1

	var testResults errorResults

	for i := range clients {
		wg.Add(1)
		go testInteractiveSession(client, i, &wg, &testResults)
	}

	wg.Wait()

	testResults.mu.Lock()
	assert.Empty(t, testResults.errs)
	testResults.mu.Unlock()
}

func testInteractiveSession(client *ssh.Client, id int, wg *sync.WaitGroup, testResults *errorResults) {
	var errors []error
	session, stdout, stderr, stdin, err := startInteractiveSession(client)
	if err != nil {
		errors = append(errors, fmt.Errorf("could not start interactive session: %s", err))
	}

	defer session.Close()
	defer wg.Done()

	cmd := fmt.Sprintf("echo \"%d: result=$((2+2))\" && exit", id)
	expectedOutput := fmt.Sprintf("%d: result=4", id)
	fmt.Fprintln(stdin, cmd)

	if err := session.Wait(); err != nil {
		errors = append(errors, fmt.Errorf("error waiting session: %s", err))
	}

	stdErrOutput := stderr.String()
	if len(stdErrOutput) != 0 {
		errors = append(errors, fmt.Errorf("expected empty stderr, but found: %s", stdErrOutput))
	}

	stdoutOutput := stdout.String()
	if !strings.Contains(stdoutOutput, expectedOutput) {
		errors = append(errors, fmt.Errorf("expected command output in stdout"))
	}

	testResults.mu.Lock()
	testResults.errs = append(testResults.errs, errors...)
	testResults.mu.Unlock()
}
