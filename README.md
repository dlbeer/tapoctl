# tapoctl

Command-line control of Tapo smart plugs (P100, P110, P110M, ...) on the
local network. Needs only the system `python3` (3.6+); no third-party
packages or virtualenv.

## Building

    make            # produces ./tapoctl, a single executable file
    make install    # copies it to /usr/local/bin (PREFIX=... to change)
    make test       # runs unit tests

`./tapoctl` is a Python zipapp, so you can copy that one file to any host with
`python3` and run it. The version string (`tapoctl --version`) is generated at
build time from `git describe`, the build date and `user@host`.

You can also run it straight from the source tree with `PYTHONPATH=src python3 -m tapoctl`.

## Usage

    tapoctl login you@example.com   # prompts for password, finds devices
    tapoctl list                    # show account and known devices
    tapoctl sync                    # rediscover devices
    tapoctl on  "Desk lamp"         # by name (case-insensitive)...
    tapoctl off 192.168.0.100       # ...or by IP address
    tapoctl status "Desk lamp"

Use `-c FILE` to choose a config file other than `~/.tapoctl`. The file is
JSON, created with mode 0600, and holds your username and password in
plaintext together with the device list.

## How devices are found

`login` and `sync` broadcast a TP-Link discovery probe (UDP port 20002) on
every local interface. Each Tapo device that replies is then contacted with
your credentials to read the name you gave it in the Tapo app. This also
verifies the credentials: `login` refuses to save them if every device rejects
them.

If your plugs are on a different subnet from the host, broadcasts won't reach
them. In that case, pass extra probe addresses, such as that subnet's broadcast
address (if your router forwards it) or the plugs' IP addresses:

    tapoctl sync 192.168.0.255
    tapoctl sync 192.168.0.100 192.168.0.101

If a device named on the command line can't be reached at its saved address
(say its DHCP lease changed), tapoctl searches the local network for it by MAC
address and updates the saved IP.

## Protocol notes

Devices are controlled locally using the KLAP protocol used by current Tapo
firmware (v2, with v1 fallback). Devices that only speak the older
"securePassthrough" protocol are skipped during discovery. AES-128-CBC is
implemented in pure Python (`src/tapoctl/aes.py`), because the standard library
has no block cipher.

## Licence

Public domain. This code was generated entirely by an AI model (Claude), so
it is dedicated to the public domain under the Unlicense; see `LICENSE`.
