"""Runtime instrumentation for Python MCP servers.

Injected by placing this file's directory on PYTHONPATH; CPython imports
``sitecustomize`` automatically at interpreter start, before the server module.
Like the Node shim this only observes -- it records effects so that behaviour can
be compared with what the server declares, and stops nothing.
"""
import json
import os
import time

_TRACE = os.environ.get("SKILLCHECK_TRACE")

if _TRACE:
    _seen = set()
    _budget = [5000]

    def _emit(kind, detail):
        try:
            if _budget[0] <= 0:
                return
            key = (kind, detail)
            if key in _seen:
                return
            _seen.add(key)
            _budget[0] -= 1
            line = json.dumps({
                # Absolute epoch; the runner rebases it against its own start.
                "t": int(time.time() * 1000),
                "kind": kind,
                "detail": str(detail)[:300],
                "frame": "",
            })
            with open(_TRACE, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception:
            pass

    def _audit(event, args):
        try:
            if event == "open":
                path = str(args[0])
                if path == _TRACE:
                    return
                mode = str(args[1]) if len(args) > 1 and args[1] else "r"
                _emit("fs.write" if any(c in mode for c in "wxa+") else "fs.read", path)
            elif event in ("os.remove", "os.rename", "os.mkdir", "shutil.copyfile"):
                _emit("fs.write", args[0])
            elif event == "socket.connect":
                addr = args[1] if len(args) > 1 else args[0]
                _emit("net.connect", _fmt_addr(addr))
            elif event == "socket.getaddrinfo":
                _emit("net.dns", args[0])
            elif event in ("subprocess.Popen", "os.system", "os.exec"):
                _emit("process.exec", args[0] if args else "")
            elif event == "urllib.Request":
                _emit("net.connect", args[0])
        except Exception:
            pass

    def _fmt_addr(addr):
        if isinstance(addr, (tuple, list)) and len(addr) >= 2:
            return "%s:%s" % (addr[0], addr[1])
        return str(addr)

    # PEP 578 audit hooks see the real syscall boundary, so no monkey-patching of
    # the standard library is needed and there is nothing for a caller to rebind.
    try:
        import sys
        sys.addaudithook(_audit)
    except Exception:
        pass

    _SECRETISH = ("SECRET", "TOKEN", "PASSWORD", "API_KEY", "APIKEY",
                  "PRIVATE_KEY", "ACCESS_KEY", "CREDENTIAL", "SESSION", "AUTH")

    class _EnvWatcher(dict):
        def __getitem__(self, key):
            if any(s in str(key).upper() for s in _SECRETISH):
                _emit("env.read", key)
            return super().__getitem__(key)

    try:
        os.environ._data = os.environ._data  # touch, fail fast on odd platforms
        _orig_getitem = type(os.environ).__getitem__

        def _patched(self, key):
            if any(s in str(key).upper() for s in _SECRETISH):
                _emit("env.read", key)
            return _orig_getitem(self, key)

        type(os.environ).__getitem__ = _patched
    except Exception:
        pass

    # Taint check on outbound writes. PEP 578 has no audit event for send(), so
    # the socket methods are wrapped directly; SSLSocket is wrapped too because
    # its send path is where the plaintext still exists.
    _CANARIES = [c for c in os.environ.pop("SKILLCHECK_CANARIES", "").split(",") if c]

    def _scan(data, sock):
        try:
            if not _CANARIES or data is None:
                return
            text = bytes(data).decode("utf-8", "ignore") if not isinstance(data, str) else data
            try:
                peer = "%s:%s" % sock.getpeername()[:2]
            except Exception:
                peer = "unknown"
            for c in _CANARIES:
                if c in text:
                    _emit("exfil.canary", "%s -> %s" % (c, peer))
        except Exception:
            pass

    def _wrap(cls, name):
        real = getattr(cls, name, None)
        if real is None:
            return
        def patched(self, data, *args, **kwargs):
            _scan(data, self)
            return real(self, data, *args, **kwargs)
        try:
            setattr(cls, name, patched)
        except Exception:
            pass

    if _CANARIES:
        try:
            import socket as _socket_mod
            for _n in ("send", "sendall", "sendto"):
                _wrap(_socket_mod.socket, _n)
        except Exception:
            pass
        try:
            import ssl as _ssl_mod
            for _n in ("send", "sendall", "write"):
                _wrap(_ssl_mod.SSLSocket, _n)
        except Exception:
            pass

    _emit("probe.ready", str(os.getpid()))
