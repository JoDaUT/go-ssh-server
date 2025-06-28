# go-ssh-server

This repository provides a minimal implementation of an SSH server in Go, created for educational purposes. It demonstrates the basics of an SSH server, but **should not** be used in production environments due to missing features like port forwarding, subsystems, and robust security practices. That said, it can be used as a starting point for creating simple mock SSH servers for integration testing.

## Key Features
- Supports basic **exec** and **shell** requests with **pty** allocation.
- Public key authentication
- Allowlist control access

## Limitations
- **Not production-ready**: Lacks critical SSH protocol features and security measures.
- **Limited compatibility**: May not work with all SSH clients, and there’s no guarantee of full compatibility.
- **No port forwarding, SFTP or subsystems**: These are essential features for a full SSH server but are not implemented in this project. I might add them in the future.

## Inspiration
This project is inspired mostly by the following resources:
- **Gopher Academy (2015)** - [Building an SSH Server in Go](https://blog.gopheracademy.com/advent-2015/ssh-server-in-go/)
- **Gliderlabs (2025)** - [Gliderlabs SSH Package](https://github.com/gliderlabs/ssh)

## Usage

This project is primarily intended for educational purposes or as a starting point for building mock SSH servers in test environments. You can easily integrate or modify it to suit your needs for local testing. 

If you're looking for a more polished solution, I encourage you to check out the [Gliderlabs SSH server implementation](https://github.com/gliderlabs/ssh), which may be a better fit for mocking SSH servers in production-like environments.


## Configuration

This application requires a `config.yaml` file to be created in the same folder as the executable. See `config.yaml.example` for a template. Essentially, it mimics some aspects of the `/etc/ssh/sshd_config` file.

### Required Fields:
- **interface**: The network interface the server will listen on. Set it to `0.0.0.0` to listen on all available network interfaces.
- **port**: The port the server will use to listen for incoming connections. Choose any available port on your system.
- **authorized_key_file**: The path to a file containing the public keys authorized to be used, similar to the `.ssh/authorized_keys` file.
- **private_key_file**: The private key that corresponds to one of the public keys in the `authorized_key_file`. If a connecting client uses a private key that doesn’t match any public key in the file, the connection will be rejected.
- **authorized_users**: A list of authorized users, e.g., `[user1, user2]`.

### How to run

If you just want to run the application without compiling it, you can use:

```bash
go run .
```

To build and run the application execute:
```
go build -o sshserver && ./sshserver
```

## Using an SSH Client to Connect

You can interact with the application using any SSH client, including the default `ssh` client available on most systems.

There are two supported modes: running a single command (`exec`) and allocating a terminal (`shell`). For both modes, you must specify the correct user, private key file, and port.

### Run a Single Command:
To execute a single command, use the following format:

```bash
ssh -i <private_key_file_path> <user>@127.0.0.1 -p <port> <command>
```

Example:
```bash
# Execute the 'pwd' command
ssh -i ~/.ssh/testkey myuser@127.0.0.1 -p 8001 pwd

# Execute the 'echo' command with args
ssh -i ~/.ssh/testkey myuser@127.0.0.1 -p 8001 echo "hello world"
```

If you pass `/bin/bash` as the command, a Bash session will be started. However, interactive commands might not work well in this case because the exec mode does not allocate a pseudo-terminal by default.

### Allocate a Terminal (Shell):

To start an interactive session, you can simply omit the command. The default SSH client on Linux and macOS will automatically send a pty-req (pseudo-terminal request) and a shell request, allowing you to allocate a terminal for interactive use.

Example:
```bash
# Connect and allocate a pseudo-terminal for an interactive session
ssh -i ~/.ssh/testkey myuser@127.0.0.1 -p 8001

# Start an interactive Python interpreter
python3
```

### Connecting from a Remote Computer

This SSH server is fully functional, and if you allow traffic from the outside, you can connect from a remote computer.

#### Open the Port on the Firewall:
To allow external connections to the server, you'll need to open the appropriate port on your firewall. Below are instructions for some common Linux firewall tools.

##### For Debian-based Systems (e.g., Ubuntu):
If you're using `ufw` (Uncomplicated Firewall), run the following command to allow traffic on port `8080`:

```bash
sudo ufw allow 8080/tcp
```
##### For Red Hat-based Systems (e.g., CentOS, Fedora):

If you're using `firewalld`, allow traffic on port 8080 by running:
```bash
sudo firewall-cmd --add-port=8080/tcp
```

##### For systems Using iptables:

If you're managing the firewall with iptables, add a rule to allow traffic on port 8001 (or whichever port you configured):
```bash
sudo iptables -A INPUT -p tcp --dport 8001 -j ACCEPT
```
#### Remember to Revert Changes:

Once you're done testing or playing with the application, remember to undo the firewall and iptables changes to close the port again and ensure your system remains secure or use a docker container to run the application.


## Additional resources 

If you’d like to dive deeper into the inner workings of SSH and the messages exchanged to authenticate and establish a connection, here are some essential RFCs for SSH:
- The Internet Society - 2006 - [RFC 4250](https://www.rfc-editor.org/rfc/rfc4250)
- The Internet Society - 2006 - [RFC 4251](https://www.rfc-editor.org/rfc/rfc4251)
- The Internet Society - 2006 - [RFC 4252](https://www.rfc-editor.org/rfc/rfc4252)
- The Internet Society - 2006 - [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253)
- The Internet Society - 2006 - [RFC 4254](https://www.rfc-editor.org/rfc/rfc4254)