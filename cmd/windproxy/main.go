package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"time"

	"github.com/igolaizola/windproxy"
	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/peterbourgon/ff/v3/ffyaml"
)

// Build flags
var version = ""
var commit = ""
var date = ""

func main() {
	// Create signal based context
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Launch command
	cmd := newCommand()
	if err := cmd.ParseAndRun(ctx, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func newCommand() *ffcli.Command {
	fs := flag.NewFlagSet("windproxy", flag.ExitOnError)

	return &ffcli.Command{
		ShortUsage: "windproxy [flags] <subcommand>",
		FlagSet:    fs,
		Exec: func(context.Context, []string) error {
			return flag.ErrHelp
		},
		Subcommands: []*ffcli.Command{
			newVersionCommand(),
			newRunCommand(),
			newListProxies(),
			newListLocations(),
		},
	}
}

func newVersionCommand() *ffcli.Command {
	return &ffcli.Command{
		Name:       "version",
		ShortUsage: "windproxy version",
		ShortHelp:  "print version",
		Exec: func(ctx context.Context, args []string) error {
			v := version
			if v == "" {
				if buildInfo, ok := debug.ReadBuildInfo(); ok {
					v = buildInfo.Main.Version
				}
			}
			if v == "" {
				v = "dev"
			}
			versionFields := []string{v}
			if commit != "" {
				versionFields = append(versionFields, commit)
			}
			if date != "" {
				versionFields = append(versionFields, date)
			}
			fmt.Println(strings.Join(versionFields, " "))
			return nil
		},
	}
}

func newRunCommand() *ffcli.Command {
	cmd := "run"
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	_ = fs.String("config", "", "config file (optional)")

	cfg := configFlags(fs)

	return &ffcli.Command{
		Name:       cmd,
		ShortUsage: fmt.Sprintf("windproxy %s [flags] <key> <value data...>", cmd),
		Options: []ff.Option{
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(ffyaml.Parser),
			ff.WithEnvVarPrefix("WINDPROXY"),
		},
		ShortHelp: fmt.Sprintf("windproxy %s command", cmd),
		FlagSet:   fs,
		Exec: func(ctx context.Context, args []string) error {
			return windproxy.Run(ctx, cfg)
		},
	}
}

func newListProxies() *ffcli.Command {
	cmd := "list-proxies"
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	_ = fs.String("config", "", "config file (optional)")

	cfg := configFlags(fs)

	return &ffcli.Command{
		Name:       cmd,
		ShortUsage: fmt.Sprintf("windproxy %s [flags]", cmd),
		Options: []ff.Option{
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(ffyaml.Parser),
			ff.WithEnvVarPrefix("WINDPROXY"),
		},
		ShortHelp: fmt.Sprintf("windproxy %s command", cmd),
		FlagSet:   fs,
		Exec: func(ctx context.Context, args []string) error {
			return windproxy.ListProxies(ctx, cfg)
		},
	}
}

func newListLocations() *ffcli.Command {
	cmd := "list-locations"
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	_ = fs.String("config", "", "config file (optional)")

	cfg := configFlags(fs)

	return &ffcli.Command{
		Name:       cmd,
		ShortUsage: fmt.Sprintf("windproxy %s [flags]", cmd),
		Options: []ff.Option{
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(ffyaml.Parser),
			ff.WithEnvVarPrefix("WINDPROXY"),
		},
		ShortHelp: fmt.Sprintf("windproxy %s command", cmd),
		FlagSet:   fs,
		Exec: func(ctx context.Context, args []string) error {
			return windproxy.ListLocations(ctx, cfg)
		},
	}
}

func configFlags(fs *flag.FlagSet) *windproxy.Config {
	var cfg windproxy.Config
	fs.StringVar(&cfg.Location, "location", "", "desired proxy location. Default: best location")
	fs.BoolVar(&cfg.Random, "random", false, "use random location")
	fs.StringVar(&cfg.BindAddress, "bind-address", "127.0.0.1:28080", "HTTP proxy listen address")
	fs.IntVar(&cfg.Verbosity, "verbosity", 20, "logging verbosity "+
		"(10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical)")
	fs.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "timeout for network operations")
	fs.StringVar(&cfg.Proxy, "proxy", "", "sets base proxy to use for all dial-outs. "+
		"Format: <http|https|socks5|socks5h>://[login:password@]host[:port] "+
		"Examples: http://user:password@192.168.1.1:3128, socks5://10.0.0.1:1080")
	// TODO: implement DNS resolving or remove it
	fs.StringVar(&cfg.Resolver, "resolver", "",
		"Use DNS/DoH/DoT/DoQ resolver for all dial-outs. "+
			"See https://github.com/ameshkov/dnslookup/ for upstream DNS URL format. "+
			"Examples: https://1.1.1.1/dns-query, quic://dns.adguard.com")
	fs.StringVar(&cfg.CAFile, "cafile", "", "use custom CA certificate bundle file")
	fs.StringVar(&cfg.ClientAuthSecret, "auth-secret", windproxy.DEFAULT_CLIENT_AUTH_SECRET, "client auth secret")
	fs.StringVar(&cfg.StateFile, "state-file", "wndstate.json", "file name used to persist "+
		"Windscribe API client state")
	fs.StringVar(&cfg.Username, "username", "", "username for login")
	fs.StringVar(&cfg.Password, "password", "", "password for login")
	fs.StringVar(&cfg.Tfacode, "2fa", "", "2FA code for login")
	fs.StringVar(&cfg.FakeSNI, "fake-sni", "com", "fake SNI to use to contact windscribe servers")
	fs.BoolVar(&cfg.ForceColdInit, "force-cold-init", false, "force cold init")
	fs.StringVar(&cfg.RefreshPath, "refresh-path", "/windproxy-refresh", "path to trigger endpoint refresh")
	return &cfg
}
