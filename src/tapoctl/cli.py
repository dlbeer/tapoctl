"""tapoctl command-line interface."""

import argparse
import base64
import getpass
import ipaddress
import sys

from . import discover
from .config import Config, default_path
from .klap import AuthError, Device, TapoError

try:
    from ._version import VERSION
except ImportError:
    VERSION = "unknown (not built with make)"


def _decode_name(s):
    try:
        return base64.b64decode(s, validate=True).decode()
    except (ValueError, UnicodeDecodeError):
        return s


def scan(cfg, targets):
    """Discover devices and query each one for its name.

    Returns (devices, auth_ok, auth_failed).
    """
    found = discover.discover(targets)
    devices, ok, failed = [], 0, 0
    for ip in sorted(found, key=ipaddress.ip_address):
        info = found[ip]
        if info.get("mgt_encrypt_schm", {}).get("encrypt_type") != "KLAP":
            print("tapoctl: %s (%s): unsupported protocol, skipping" %
                  (ip, info.get("device_model", "?")), file=sys.stderr)
            continue
        entry = {
            "name": None,
            "ip": ip,
            "mac": info.get("mac"),
            "model": info.get("device_model"),
            "type": info.get("device_type"),
            "device_id": info.get("device_id"),
        }
        try:
            di = Device(ip, cfg.username, cfg.password).get_info()
            entry["name"] = _decode_name(di.get("nickname", ""))
            entry["model"] = di.get("model", entry["model"])
            ok += 1
        except AuthError as e:
            print("tapoctl: %s" % e, file=sys.stderr)
            failed += 1
            continue
        except (TapoError, OSError) as e:
            print("tapoctl: %s: %s" % (ip, e), file=sys.stderr)
            continue
        devices.append(entry)
    return devices, ok, failed


def cmd_login(cfg, args):
    password = getpass.getpass("Password for %s: " % args.username)
    cfg.username = args.username
    cfg.password = password
    print("Searching for devices...")
    devices, ok, failed = scan(cfg, args.address)
    if failed and not ok:
        raise SystemExit("tapoctl: credentials rejected; nothing saved")
    if not ok:
        print("tapoctl: warning: no devices found, so credentials could not "
              "be verified", file=sys.stderr)
    cfg.devices = devices
    cfg.save()
    print("Saved credentials and %d device(s) to %s" %
          (len(devices), cfg.path))
    _print_devices(cfg)


def cmd_sync(cfg, args):
    cfg.require_login()
    devices, ok, failed = scan(cfg, args.address)
    if failed and not ok:
        raise SystemExit("tapoctl: credentials rejected; device list "
                         "not updated")
    cfg.devices = devices
    cfg.save()
    print("Found %d device(s)" % len(devices))
    _print_devices(cfg)


def _print_devices(cfg):
    if not cfg.devices:
        print("No devices.")
        return
    rows = [(d.get("name") or "", d.get("ip") or "", d.get("model") or "",
             d.get("mac") or "") for d in cfg.devices]
    hdr = ("NAME", "IP", "MODEL", "MAC")
    w = [max(len(r[i]) for r in rows + [hdr]) for i in range(4)]
    for r in [hdr] + rows:
        print("  ".join(c.ljust(w[i]) for i, c in enumerate(r)).rstrip())


def cmd_list(cfg, args):
    print("Account: %s" % (cfg.username or "(not logged in)"))
    print()
    _print_devices(cfg)


def resolve(cfg, spec):
    """Map a device name or IP to (ip, config entry or None)."""
    try:
        ipaddress.ip_address(spec)
        for d in cfg.devices:
            if d.get("ip") == spec:
                return spec, d
        return spec, None
    except ValueError:
        pass
    matches = [d for d in cfg.devices if d.get("name") == spec]
    if not matches:
        matches = [d for d in cfg.devices
                   if (d.get("name") or "").lower() == spec.lower()]
    if len(matches) > 1:
        raise SystemExit("tapoctl: device name '%s' is ambiguous; use an "
                         "IP address" % spec)
    if not matches:
        raise SystemExit("tapoctl: unknown device '%s' (try 'tapoctl sync' "
                         "or 'tapoctl list')" % spec)
    return matches[0]["ip"], matches[0]


def _with_device(cfg, spec, fn):
    """Run fn(Device). If a named device can't be reached, rediscover it
    (its DHCP address may have changed) and retry once."""
    cfg.require_login()
    ip, entry = resolve(cfg, spec)
    try:
        return fn(Device(ip, cfg.username, cfg.password)), entry
    except OSError as e:
        if entry is None or not entry.get("mac"):
            raise SystemExit("tapoctl: %s: %s" % (ip, e))
        print("tapoctl: %s unreachable at %s; searching..." %
              (spec, ip), file=sys.stderr)
        for new_ip, info in discover.discover().items():
            if info.get("mac") == entry["mac"]:
                break
        else:
            raise SystemExit("tapoctl: %s: %s (not found on network)" %
                             (spec, e))
        entry["ip"] = new_ip
        cfg.save()
        try:
            return fn(Device(new_ip, cfg.username, cfg.password)), entry
        except OSError as e:
            raise SystemExit("tapoctl: %s: %s" % (new_ip, e))
    except TapoError as e:
        raise SystemExit("tapoctl: %s" % e)


def _label(spec, entry):
    if entry and entry.get("name") and entry["name"] != spec:
        return "%s (%s)" % (spec, entry["name"])
    if entry and entry.get("ip") and entry["ip"] != spec:
        return "%s (%s)" % (spec, entry["ip"])
    return spec


def cmd_power(cfg, args):
    on = args.command == "on"
    _, entry = _with_device(cfg, args.device, lambda d: d.set_power(on))
    print("%s: %s" % (_label(args.device, entry), "on" if on else "off"))


def cmd_status(cfg, args):
    info, entry = _with_device(cfg, args.device, lambda d: d.get_info())
    print("%s: %s" % (_label(args.device, entry),
                      "on" if info.get("device_on") else "off"))


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="tapoctl", description="Control Tapo smart plugs on the "
        "local network.")
    p.add_argument("--version", action="version",
                   version="tapoctl " + VERSION)
    p.add_argument("-c", metavar="FILE", dest="config",
                   default=default_path(),
                   help="config file (default: ~/.tapoctl)")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    addr_help = ("extra address(es) to probe, e.g. a remote subnet's "
                 "broadcast address or a device IP")
    s = sub.add_parser("login", help="store credentials and find devices")
    s.add_argument("username", help="Tapo account e-mail address")
    s.add_argument("address", nargs="*", help=addr_help)
    s.set_defaults(fn=cmd_login)

    s = sub.add_parser("sync", help="refresh the list of devices")
    s.add_argument("address", nargs="*", help=addr_help)
    s.set_defaults(fn=cmd_sync)

    s = sub.add_parser("list", help="show account and saved devices")
    s.set_defaults(fn=cmd_list)

    for name, h in (("on", "switch a device on"),
                    ("off", "switch a device off"),
                    ("status", "show whether a device is on or off")):
        s = sub.add_parser(name, help=h)
        s.add_argument("device", help="device name or IP address")
        s.set_defaults(fn=cmd_status if name == "status" else cmd_power)

    args = p.parse_args(argv)
    cfg = Config.load(args.config)
    try:
        args.fn(cfg, args)
    except KeyboardInterrupt:
        raise SystemExit(130)
