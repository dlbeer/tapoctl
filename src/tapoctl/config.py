"""Persistent state in ~/.tapoctl (JSON, mode 0600)."""

import json
import os
import stat
import sys


def default_path():
    return os.path.join(os.path.expanduser("~"), ".tapoctl")


class Config:
    def __init__(self, path):
        self.path = path
        self.username = None
        self.password = None
        self.devices = []

    @classmethod
    def load(cls, path):
        cfg = cls(path)
        try:
            with open(path) as f:
                st = os.fstat(f.fileno())
                data = json.load(f)
        except FileNotFoundError:
            return cfg
        except ValueError as e:
            raise SystemExit("tapoctl: %s: invalid config: %s" % (path, e))
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            print("tapoctl: warning: %s is accessible by other users "
                  "(should be mode 0600)" % path, file=sys.stderr)
        cfg.username = data.get("username")
        cfg.password = data.get("password")
        cfg.devices = data.get("devices", [])
        return cfg

    def save(self):
        data = {
            "username": self.username,
            "password": self.password,
            "devices": self.devices,
        }
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def require_login(self):
        if not self.username or self.password is None:
            raise SystemExit("tapoctl: no credentials stored in %s; run "
                             "'tapoctl login <username>' first" % self.path)
