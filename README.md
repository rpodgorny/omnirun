[![Build Status](https://travis-ci.org/rpodgorny/unionfs-fuse.svg?branch=master)](https://travis-ci.org/rpodgorny/unionfs-fuse)
[![Gratipay](http://img.shields.io/gratipay/rpodgorny.svg)](https://gratipay.com/rpodgorny/)

# omnirun

Run a command or a scripts on multiple hosts.

## Features

- run simple commands or entire scripts
- interactive and non-interactive mode (this is what salt, ansible and other don't have!)
- single-terminal or tmux operation (run commands in parallel)
- support for sshpass to enter passwords on command line

## Usage

```
> omnirun -h
Omnirun. Run command on multiple hosts.

Usage:
  omnirun [options] <hosts>
  omnirun [options] <hosts> <command>
  omnirun [options] <hosts> [--sudo] --script <script>
  omnirun [options] <hosts> --copy-keys

Options:
  --no-strict-host-key-checking  Disable ssh host key checking.
  --interactive                  Interactive mode. You have to disconnect manually.
  -p <num>                       Number of parallel processes to run.
  -4                             Force connection over IPv4.
  -6                             Force connection over IPv6.
  --sudo                         Use sudo on remote system.
  --copy-keys                    Copy local ssh keys to remote servers.
  -t                             Force tty allocation on the remote host (add -t to ssh options).
  --keep-open=<0,1,2,...,unknown,nonzero>
                                 Keep the window open when exit status is among the enumerated.
  --retry-on=<0,1,2,...,unknown,nonzero>
                                 Keep running the command while the exit status is among the enumerated.
  --retry-limit=<n>              Maximum number of retries in retry mode.
  --terse                        Be terse when printing final result stats.

Arguments:
  <hosts>    Hosts to connect to.
  <command>  Command to run.

Host specification:
  [<username>[:<password>]@]<hostname>[:<port>] where <hostname> can be:
    * plain hostname (server34.company.com)
    * ip address (192.168.22.44)
    * ip address with range (192.168.22.[1-57)
    * tag - has to start with hash (#linux)
```

## Examples

```
> echo 'username1:password1@host1 #linux #server
username2@host2 #linux client
host3 #windows #client' > ~/.omnirun.conf

> omnirun \#linux 'uname -a'
(asks you for username and password if needed)

> omnirun \#client 'ls /'

> omnirun \#linux -p 10 'sudo apt-get update'
(runs tasks in parallel)

```

...TBD: add more examples
