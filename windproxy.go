package windproxy

import (
	"context"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/igolaizola/windproxy/pkg/windscribe"
	xproxy "golang.org/x/net/proxy"
)

type Config struct {
	Location         string
	Random           bool
	BindAddress      string
	Verbosity        int
	Timeout          time.Duration
	Proxy            string
	Resolver         string
	CAFile           string
	ClientAuthSecret string
	StateFile        string
	Username         string
	Password         string
	Tfacode          string
	FakeSNI          string
	ForceColdInit    bool
	RefreshPath      string
}

func Run(ctx context.Context, cfg *Config) error {
	lg := newLogger(cfg.Verbosity)
	defer lg.Close()

	wndc, err := newClient(cfg, lg)
	if err != nil {
		return err
	}

	var dialer ContextDialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	var caPool *x509.CertPool
	if cfg.CAFile != "" {
		caPool = x509.NewCertPool()
		certs, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			err := fmt.Errorf("couldn't read CA file: %w", err)
			_ = lg.main.Error(err.Error())
			return err
		}
		if ok := caPool.AppendCertsFromPEM(certs); !ok {
			err := errors.New("couldn't load certificates from CA file")
			_ = lg.main.Error(err.Error())
			return err
		}
	}

	var serverList windscribe.ServerList

	var defaultServer *server
	if cfg.Location != "" || cfg.Random {
		serverList, err = wndc.ServerList(ctx)
		if err != nil {
			// _ = mainLogger.Critical("Server list retrieve failed: %v", err)
			return fmt.Errorf("couldn't retrieve server list: %w", err)
		}
		// Pick a server based on the location or randomly
		var location string
		if !cfg.Random {
			location = cfg.Location
		}
		defaultServer, err = pickServer(serverList, location)
		if err != nil {
			return fmt.Errorf("couldn't pick a server: %w", err)
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
		bestLocation, err := wndc.BestLocation(ctx)
		cancel()
		if err != nil {
			err := fmt.Errorf("couldn't get best location endpoint: %w", err)
			_ = lg.main.Critical(err.Error())
			return err
		}
		defaultServer = &server{
			hostname: bestLocation.Hostname,
			// TODO: check if this is the same as country/city
			location: bestLocation.LocationName,
		}
	}

	// Get the address and hostname dynamically
	servers := sync.Map{}
	servers.Store("", defaultServer)

	getAddress := func(key string, value string) (string, string) {
		switch key {
		case "random":
			// Pick a new server
			srv, err := pickServer(serverList, "")
			if err != nil {
				_ = lg.main.Error("Couldn't pick a server: %v", err)
				return net.JoinHostPort(defaultServer.hostname, strconv.FormatUint(uint64(ASSUMED_PROXY_PORT), 10)), defaultServer.hostname
			}
			return net.JoinHostPort(srv.hostname, strconv.FormatUint(uint64(ASSUMED_PROXY_PORT), 10)), srv.hostname
		case "location":
			// Pick a new server
			value := strings.ReplaceAll(value, "-", " ")
			value = strings.ReplaceAll(value, "_", "/")
			id := fmt.Sprintf("location:%s", value)
			v, ok := servers.Load(id)
			if !ok {
				srv, err := pickServer(serverList, value)
				if err != nil {
					_ = lg.main.Error("Couldn't pick a server for %s: %v", err)
					return net.JoinHostPort(defaultServer.hostname, strconv.FormatUint(uint64(ASSUMED_PROXY_PORT), 10)), defaultServer.hostname
				}
				servers.Store(id, srv)
				return net.JoinHostPort(srv.hostname, strconv.FormatUint(uint64(ASSUMED_PROXY_PORT), 10)), srv.hostname
			}
			srv := v.(*server)
			return net.JoinHostPort(srv.hostname, strconv.FormatUint(uint64(ASSUMED_PROXY_PORT), 10)), srv.hostname
		case "id":
			id := fmt.Sprintf("id:%s", value)
			// Load the server
			v, ok := servers.Load(id)
			if !ok {
				srv := defaultServer
				if cfg.Random {
					srv, err = pickServer(serverList, "")
					if err != nil {
						_ = lg.main.Error("Couldn't pick a server for %s: %v", id, err)
					}
				}
				servers.Store(id, srv)
				return net.JoinHostPort(srv.hostname, strconv.FormatUint(uint64(ASSUMED_PROXY_PORT), 10)), srv.hostname
			}
			srv := v.(*server)
			return net.JoinHostPort(srv.hostname, strconv.FormatUint(uint64(ASSUMED_PROXY_PORT), 10)), srv.hostname
		default:
			v, ok := servers.Load("")
			if !ok {
				_ = lg.main.Error("Couldn't load the default server")
				return net.JoinHostPort(defaultServer.hostname, strconv.FormatUint(uint64(ASSUMED_PROXY_PORT), 10)), defaultServer.hostname
			}
			srv := v.(*server)
			return net.JoinHostPort(srv.hostname, strconv.FormatUint(uint64(ASSUMED_PROXY_PORT), 10)), srv.hostname
		}
	}
	refreshAddress := func(key, value string) {
		switch key {
		case "random":
			return
		case "location":
			value := strings.ReplaceAll(value, "-", " ")
			value = strings.ReplaceAll(value, "_", "/")
			id := fmt.Sprintf("location:%s", value)
			srv, err := pickServer(serverList, value)
			if err != nil {
				_ = lg.main.Error("Couldn't pick a server for %s: %v", id, err)
				return
			}
			servers.Store(id, srv)
		case "id":
			id := fmt.Sprintf("id:%s", value)
			srv, err := pickServer(serverList, value)
			if err != nil {
				_ = lg.main.Error("Couldn't pick a server for %s: %v", id, err)
				return
			}
			servers.Store(id, srv)
		default:
			var location string
			if !cfg.Random {
				location = cfg.Location
			}
			srv, err := pickServer(serverList, location)
			if err != nil {
				_ = lg.main.Error("Couldn't pick a server: %v", err)
				return
			}
			servers.Store("", srv)
		}
	}

	auth := func() string {
		return basic_auth_header(wndc.GetProxyCredentials())
	}

	handlerDialer := NewProxyDialer(getAddress, cfg.FakeSNI, auth, caPool, dialer)
	_ = lg.main.Info("Endpoint: %s", defaultServer.hostname)
	_ = lg.main.Info("Starting proxy server...")

	handler := NewProxyHandler(handlerDialer, lg.proxy, refreshAddress, cfg.RefreshPath)
	_ = lg.main.Info("Init complete.")

	server := &http.Server{
		Addr:    cfg.BindAddress,
		Handler: handler,
	}
	go func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			_ = lg.main.Critical("Server terminated with a reason: %v", err)
		}
	}()

	<-ctx.Done()
	_ = lg.main.Info("Shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	_ = server.Shutdown(shutdownCtx)
	cancel()

	return nil
}

func ListLocations(ctx context.Context, cfg *Config) error {
	lg := newLogger(cfg.Verbosity)
	defer lg.Close()

	wndc, err := newClient(cfg, lg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	serverList, err := wndc.ServerList(ctx)
	if err != nil {
		// _ = mainLogger.Critical("Server list retrieve failed: %v", err)
		return fmt.Errorf("couldn't retrieve server list: %w", err)
	}

	printLocations(serverList)

	return nil
}

func ListProxies(ctx context.Context, cfg *Config) error {
	lg := newLogger(cfg.Verbosity)
	defer lg.Close()

	wndc, err := newClient(cfg, lg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	serverList, err := wndc.ServerList(ctx)
	if err != nil {
		// _ = mainLogger.Critical("Server list retrieve failed: %v", err)
		return fmt.Errorf("couldn't retrieve server list: %w", err)
	}
	user, pass := wndc.GetProxyCredentials()
	printProxies(user, pass, serverList)

	return nil
}

type logger struct {
	main     *CondLogger
	proxy    *CondLogger
	resolver *CondLogger
	writer   *LogWriter
}

func (l *logger) Close() {
	l.writer.Close()
}

func newLogger(verbosity int) *logger {
	logWriter := NewLogWriter(os.Stderr)

	return &logger{
		writer: logWriter,
		main: NewCondLogger(log.New(logWriter, "MAIN    : ",
			log.LstdFlags|log.Lshortfile),
			verbosity),
		proxy: NewCondLogger(log.New(logWriter, "PROXY   : ",
			log.LstdFlags|log.Lshortfile),
			verbosity),
		resolver: NewCondLogger(log.New(logWriter, "RESOLVER: ",
			log.LstdFlags|log.Lshortfile),
			verbosity),
	}
}

const (
	DEFAULT_CLIENT_AUTH_SECRET        = "952b4412f002315aa50751032fcaab03"
	ASSUMED_PROXY_PORT         uint16 = 443
)

func newClient(cfg *Config, lg *logger) (*windscribe.Client, error) {
	_ = lg.main.Info("windproxy client is starting...")

	var dialer ContextDialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	var caPool *x509.CertPool
	if cfg.CAFile != "" {
		caPool = x509.NewCertPool()
		certs, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			err := fmt.Errorf("couldn't read CA file: %w", err)
			_ = lg.main.Error(err.Error())
			return nil, err
		}
		if ok := caPool.AppendCertsFromPEM(certs); !ok {
			err := fmt.Errorf("couldn't load certificates from CA file")
			_ = lg.main.Error(err.Error())
			return nil, err
		}
	}

	if cfg.Proxy != "" {
		xproxy.RegisterDialerType("http", proxyFromURLWrapper)
		xproxy.RegisterDialerType("https", proxyFromURLWrapper)
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			err := fmt.Errorf("couldn't parse base proxy URL: %w", err)
			_ = lg.main.Critical(err.Error())
			return nil, err
		}
		pxDialer, err := xproxy.FromURL(proxyURL, dialer)
		if err != nil {
			err := fmt.Errorf("couldn't instantiate base proxy dialer: %w", err)
			_ = lg.main.Critical(err.Error())
			return nil, err
		}
		dialer = pxDialer.(ContextDialer)
	}

	if cfg.Resolver != "" {
		var err error
		dialer, err = NewResolvingDialer(cfg.Resolver, cfg.Timeout, dialer, lg.resolver)
		if err != nil {
			err := fmt.Errorf("couldn't instantiate resolver: %w", err)
			_ = lg.main.Critical("Unable to instantiate resolver: %v", err)
			return nil, err
		}
	}

	windclientDialer := dialer

	wndc, err := windscribe.NewClient(&http.Transport{
		DialContext:           windclientDialer.DialContext,
		DialTLSContext:        NewFakeSNIDialer(caPool, cfg.FakeSNI, windclientDialer).DialTLSContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	})
	if err != nil {
		err := fmt.Errorf("couldn't construct windclient: %w", err)
		_ = lg.main.Critical(err.Error())
		return nil, err
	}
	wndc.Mux.Lock()
	wndc.State.Settings.ClientAuthSecret = cfg.ClientAuthSecret
	wndc.Mux.Unlock()

	// Try to resurrect state
	state, err := maybeLoadState(cfg.ForceColdInit, cfg.StateFile)
	if err != nil {
		switch err {
		case errColdInitForced:
			_ = lg.main.Info("Cold init forced.")
		default:
			_ = lg.main.Warning("Failed to load client state: %v. It is OK for a first run. Performing cold init...", err)
		}
		err = coldInit(wndc, cfg.Username, cfg.Password, cfg.Tfacode, cfg.Timeout)
		if err != nil {
			err := fmt.Errorf("cold init failed: %w", err)
			_ = lg.main.Critical(err.Error())
			return nil, err
		}
		err = saveState(cfg.StateFile, &wndc.State)
		if err != nil {
			_ = lg.main.Error("Unable to save state file! Error: %v", err)
		}
	} else {
		wndc.Mux.Lock()
		wndc.State = *state
		wndc.Mux.Unlock()
	}
	return wndc, nil
}

type locationPair struct {
	country string
	city    string
}

func printLocations(serverList windscribe.ServerList) {
	var locs []locationPair
	for _, country := range serverList {
		for _, group := range country.Groups {
			if len(group.Hosts) > 1 {
				locs = append(locs, locationPair{country.Name, group.City})
			}
		}
	}
	if len(locs) == 0 {
		return
	}

	sort.Slice(locs, func(i, j int) bool {
		if locs[i].country < locs[j].country {
			return true
		}
		if locs[i].country == locs[j].country && locs[i].city < locs[j].city {
			return true
		}
		return false
	})

	var prevLoc locationPair
	for _, loc := range locs {
		if loc != prevLoc {
			fmt.Println(loc.country + "/" + loc.city)
			prevLoc = loc
		}
	}
}

func printProxies(username, password string, serverList windscribe.ServerList) {
	wr := csv.NewWriter(os.Stdout)
	defer wr.Flush()
	fmt.Println("Proxy login:", username)
	fmt.Println("Proxy password:", password)
	fmt.Println("Proxy-Authorization:", basic_auth_header(username, password))
	fmt.Println("")
	_ = wr.Write([]string{"location", "hostname", "port"})
	for _, country := range serverList {
		for _, group := range country.Groups {
			for _, host := range group.Hosts {
				_ = wr.Write([]string{
					country.Name + "/" + group.City,
					host.Hostname,
					strconv.FormatUint(uint64(ASSUMED_PROXY_PORT), 10),
				})
			}
		}
	}
}

func proxyFromURLWrapper(u *url.URL, next xproxy.Dialer) (xproxy.Dialer, error) {
	cdialer, ok := next.(ContextDialer)
	if !ok {
		return nil, errors.New("only context dialers are accepted")
	}

	return ProxyDialerFromURL(u, cdialer)
}

type server struct {
	hostname string
	location string
}

func pickServer(serverList windscribe.ServerList, location string) (*server, error) {
	var candidates []*server
	for _, country := range serverList {
		for _, group := range country.Groups {
			for _, host := range group.Hosts {
				currentLocation := country.Name + "/" + group.City
				if location == "" || location == currentLocation {
					candidates = append(candidates, &server{
						hostname: host.Hostname,
						location: currentLocation,
					})
				}
			}
		}
	}

	if len(candidates) == 0 {
		return nil, errors.New("no servers found")
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	return candidates[rnd.Intn(len(candidates))], nil
}

var errColdInitForced = errors.New("cold init forced")

func maybeLoadState(forceColdInit bool, filename string) (*windscribe.ClientState, error) {
	if forceColdInit {
		return nil, errColdInitForced
	}
	return loadState(filename)
}

func loadState(filename string) (*windscribe.ClientState, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var state windscribe.ClientState
	dec := json.NewDecoder(file)
	err = dec.Decode(&state)
	if err != nil {
		return nil, err
	}

	return &state, nil
}

func saveState(filename string, state *windscribe.ClientState) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "    ")
	err = enc.Encode(state)
	return err
}

func coldInit(wndc *windscribe.Client, username, password, tfacode string, timeout time.Duration) error {
	if username == "" || password == "" {
		return errors.New(`please provide "-username" and "-password" command line arguments`)
	}
	ctx, cl := context.WithTimeout(context.Background(), timeout)
	err := wndc.Session(ctx, username, password, tfacode)
	cl()
	if err != nil {
		return fmt.Errorf("session call failed: %w", err)
	}

	ctx, cl = context.WithTimeout(context.Background(), timeout)
	err = wndc.ServerCredentials(ctx)
	cl()
	if err != nil {
		return fmt.Errorf("ServerCredentials call failed: %w", err)
	}

	return nil
}
