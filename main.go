// Modified from github.com/nats-io/gnatsd/blob/master/main.go
// Copyright antmanler
// Copyright 2012-2016 Apcera Inc. All rights reserved.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/antmanler/gnatsd-jwt/jwtauth"
	"github.com/nats-io/gnatsd/server"
)

var usageStr = `
Usage: gnatsd [options]
Server Options:
    -a, --addr <host>                Bind to host address (default: 0.0.0.0)
    -p, --port <port>                Use port for clients (default: 4222)
    -P, --pid <file>                 File to store PID
    -m, --http_port <port>           Use port for http monitoring
    -ms,--https_port <port>          Use port for https monitoring
    -c, --config <file>              Configuration file
    -sl,--signal <signal>[=<pid>]    Send signal to gnatsd process (stop, quit, reopen, reload)
Logging Options:
    -l, --log <file>                 File to redirect log output
    -T, --logtime                    Timestamp log entries (default: true)
    -s, --syslog                     Log to syslog or windows event log
    -r, --remote_syslog <addr>       Syslog server addr (udp://localhost:514)
    -D, --debug                      Enable debugging output
    -V, --trace                      Trace the raw protocol
    -DV                              Debug and trace
Authorization Options:
        --user <user>                User required for connections
        --pass <password>            Password required for connections
        --auth <token>               Authorization token required for connections
        --jwt_publickey <file>       File name or folder name to load public key(s) for JWT
TLS Options:
        --tls                        Enable TLS, do not verify clients (default: false)
        --tlscert <file>             Server certificate file
        --tlskey <file>              Private key for server certificate
        --tlsverify                  Enable TLS, verify client certificates
        --tlscacert <file>           Client certificate CA for verification
Cluster Options:
        --routes <rurl-1, rurl-2>    Routes to solicit and connect
        --cluster <cluster-url>      Cluster URL for solicited routes
        --no_advertise <bool>        Advertise known cluster IPs to clients
        --connect_retries <number>   For implicit routes, number of connect retries
Common Options:
    -h, --help                       Show this message
    -v, --version                    Show version
        --help_tls                   TLS help
`

// usage will print out the flag options for the server.
func usage() {
	fmt.Printf("%s\n", usageStr)
	os.Exit(0)
}

func main() {
	// Create a FlagSet and sets the usage
	fs := flag.NewFlagSet("nats-server", flag.ExitOnError)
	fs.Usage = usage

	var pkName string
	fs.StringVar(&pkName, "jwt_publickey", "", "File name or folder name to load public key(s) for JWT.")

	// Configure the options from the flags/config file
	opts, err := server.ConfigureOptions(fs, os.Args[1:],
		server.PrintServerAndExit,
		fs.Usage,
		server.PrintTLSHelpAndDie)
	if err != nil {
		server.PrintAndDie(err.Error() + "\n" + usageStr)
	}

	var jwtAuther *jwtauth.JWTAuth
	if pkName != "" {
		fi, err := os.Stat(pkName)
		if err != nil {
			server.PrintAndDie(err.Error() + "\n" + usageStr)
			return
		}
		var pkeys []jwtauth.KeyProvider
		if fi.Mode().IsDir() {
			files, err := ioutil.ReadDir(pkName)
			server.PrintAndDie(err.Error() + "\n" + usageStr)
			for _, fi := range files {
				proivder, err := jwtauth.NewLazyPublicKeyFileProvider(filepath.Join(pkName, fi.Name()))
				if err != nil {
					server.PrintAndDie(err.Error() + "\n" + usageStr)
				}
				pkeys = append(pkeys, proivder)
			}
		} else {
			proivder, err := jwtauth.NewLazyPublicKeyFileProvider(pkName)
			if err != nil {
				server.PrintAndDie(err.Error() + "\n" + usageStr)
			}
			pkeys = []jwtauth.KeyProvider{proivder}
		}
		jwtAuther = &jwtauth.JWTAuth{
			PublicKeys: pkeys,
		}
		opts.CustomClientAuthentication = jwtAuther
	}

	// Create the server with appropriate options.
	s := server.New(opts)

	// Configure the logger based on the flags
	s.ConfigureLogger()
	if jwtAuther != nil {
		jwtAuther.SetLogger(s)
	}

	// Start things up. Block here until done.
	if err := server.Run(s); err != nil {
		server.PrintAndDie(err.Error())
	}
}
