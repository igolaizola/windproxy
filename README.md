# windproxy 🍃💻

> This project has been created as a fork of [Snawoot/windscribe-proxy](https://github.com/igolaizola/windproxy).
> The main goal is to add features to randomize the proxy location and allow to rotate the IP without restarting the server.
> The code might also be refactored to adapt it to my coding style.

Standalone Windscribe proxy client.

Just run it and it'll start a plain HTTP proxy server forwarding traffic through Windscribe proxies of your choice.
By default the application listens on 127.0.0.1:28080.

## 🚀 Features

- Cross-platform (Windows/Mac OS/Linux/Android (via shell)/\*BSD)
- Uses TLS for secure communication with upstream proxies
- Zero configuration
- Simple and straightforward
- Rotates IP address without restarting the server
- Use a random location for the proxy

## 📦 Installation

You can use the Golang binary to install windproxy:

```bash
go install github.com/igolaizola/windproxy/cmd/windproxy@latest
```

Or you can download the binary from the [releases](https://github.com/igolaizola/windproxy/releases/latest).

## 🕹️ Usage

List available locations:

```
windproxy list-locations
```

Run proxy via location of your choice:

```
windproxy run --location Germany/Frankfurt
```

Also it is possible to export proxy addresses and credentials:

```
windproxy list-proxies
```

Refresh the server IP address without restarting the server.
Launch a GET `/windproxy-refresh` request to the proxy server:

```
curl -X GET http://host:port/windproxy-refresh
```

## 🛠️ Parameters

Here is the fixed table with consistent formatting and corrected spacing:

| Argument        | Type     | Description                                                                                                                                                                                    |
| --------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2fa             | String   | 2FA code for login                                                                                                                                                                             |
| auth-secret     | String   | client auth secret (default `952b4412f002315aa50751032fcaab03`)                                                                                                                                |
| bind-address    | String   | HTTP proxy listen address (default `127.0.0.1:28080`)                                                                                                                                          |
| cafile          | String   | use custom CA certificate bundle file                                                                                                                                                          |
| fake-sni        | String   | fake SNI to use to contact windscribe servers (default "com")                                                                                                                                  |
| force-cold-init | bool     | force cold init                                                                                                                                                                                |
| location        | String   | desired proxy location. Default: best location                                                                                                                                                 |
| random          | bool     | use random location                                                                                                                                                                            |
| password        | String   | password for login                                                                                                                                                                             |
| proxy           | String   | sets base proxy to use for all dial-outs. Format: `<http\|https\|socks5\|socks5h>://[login:password@]host[:port]`. Examples: `http://user:password@192.168.1.1:3128`, `socks5://10.0.0.1:1080` |
| resolver        | String   | use DNS/DoH/DoT/DoQ resolver for all dial-outs. See https://github.com/ameshkov/dnslookup/ for upstream DNS URL format. Examples: `https://1.1.1.1/dns-query`, `quic://dns.adguard.com`        |
| state-file      | String   | file name used to persist Windscribe API client state. Default: `wndstate.json`                                                                                                                |
| timeout         | Duration | timeout for network operations. Default: `10s`                                                                                                                                                 |
| username        | String   | username for login                                                                                                                                                                             |
| verbosity       | Number   | logging verbosity (10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical). Default: `20`                                                                                              |
| refresh-path    | String   | path to trigger the endpoint refresh. Default: `/windproxy-refresh`                                                                                                                            |

## 📚 Resources

- [Snawoot/windscribe-proxy](https://github.com/igolaizola/windproxy).
