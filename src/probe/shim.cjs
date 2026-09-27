/* eslint-disable */
/**
 * Runtime instrumentation loaded into an MCP server with `--require`, before the
 * server's own entry module is evaluated.
 *
 * This is deliberately an observer and not a sandbox. It records what a server
 * does so that behaviour can be compared against what the server claims; it does
 * not stop anything, and a server that wants to evade it can. That trade is the
 * point: a scanner that blocks changes the behaviour it is trying to measure,
 * and a server that has to evade instrumentation to look clean has told you
 * something either way. Run probes in a container you are willing to discard.
 */
'use strict';

(function install() {
  var fs, path;
  try {
    fs = require('fs');
    path = require('path');
  } catch (_) { return; }

  var tracePath = process.env.SKILLCHECK_TRACE;
  if (!tracePath) return;

  // Bind originals before anything is patched, so tracing cannot trace itself.
  var appendFileSync = fs.appendFileSync.bind(fs);
  var seen = Object.create(null);
  var budget = 5000;

  function emit(kind, detail) {
    try {
      if (budget-- <= 0) return;
      var key = kind + '\u0000' + detail;
      if (seen[key]) return;            // one event per distinct effect
      seen[key] = true;
      var frame = '';
      try {
        var stack = new Error().stack.split('\n').slice(3, 6)
          .map(function (l) { return l.trim(); })
          .filter(function (l) { return l.indexOf('skillcheck') === -1 && l.indexOf('node:internal') === -1; });
        frame = stack[0] || '';
      } catch (_) {}
      // Absolute epoch: the child starts after the runner, so a relative clock
      // here would attribute tool-call effects to the startup window.
      appendFileSync(tracePath, JSON.stringify({ t: Date.now(), kind: kind, detail: detail, frame: frame }) + '\n');
    } catch (_) {}
  }

  function str(p) {
    try {
      if (typeof p === 'string') return p;
      if (Buffer.isBuffer(p)) return p.toString('utf8');
      if (p && typeof p === 'object' && p.href) return p.href;
      if (typeof p === 'number') return '<fd:' + p + '>';
      return String(p);
    } catch (_) { return '<unknown>'; }
  }

  function wrap(obj, name, kind, describe) {
    if (!obj || typeof obj[name] !== 'function') return;
    var original = obj[name];
    var patched = function () {
      try {
        var detail = describe.apply(null, arguments);
        if (detail !== null) emit(kind, detail);
      } catch (_) {}
      return original.apply(this, arguments);
    };
    try {
      Object.defineProperty(patched, 'name', { value: name });
      obj[name] = patched;
    } catch (_) {}
  }

  var firstArg = function (a) {
    var p = str(a);
    return p === tracePath ? null : p;
  };

  /* ---------------------------------------------------------- filesystem -- */
  var READ = ['readFile', 'readFileSync', 'createReadStream', 'readdir', 'readdirSync', 'realpath', 'access', 'accessSync', 'stat', 'statSync'];
  var WRITE = ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream', 'unlink', 'unlinkSync', 'rename', 'renameSync', 'rm', 'rmSync', 'rmdir', 'mkdir', 'mkdirSync', 'copyFile', 'copyFileSync', 'chmod', 'chmodSync', 'symlink'];

  // stat/access are noisy and near-universal; they are recorded only for paths
  // that matter, so the trace stays readable.
  var SENSITIVE = /\.(?:ssh|aws|gnupg|kube|npmrc|netrc|docker)\b|id_rsa|id_ed25519|credentials|\.env\b|\.claude\.json|Keychains|Cookies|Login Data|\/etc\/(?:passwd|shadow)/i;

  READ.forEach(function (name) {
    wrap(fs, name, 'fs.read', function (a) {
      var p = firstArg(a);
      if (p === null) return null;
      if ((name.indexOf('stat') === 0 || name.indexOf('access') === 0) && !SENSITIVE.test(p)) return null;
      return p;
    });
  });
  WRITE.forEach(function (name) {
    wrap(fs, name, 'fs.write', firstArg);
  });

  wrap(fs, 'open', 'fs.read', firstArg);
  wrap(fs, 'openSync', 'fs.read', firstArg);

  try {
    var fsp = require('fs/promises');
    READ.forEach(function (name) {
      wrap(fsp, name, 'fs.read', function (a) {
        var p = firstArg(a);
        if (p === null) return null;
        if ((name.indexOf('stat') === 0 || name.indexOf('access') === 0) && !SENSITIVE.test(p)) return null;
        return p;
      });
    });
    WRITE.forEach(function (name) { wrap(fsp, name, 'fs.write', firstArg); });
    wrap(fsp, 'open', 'fs.read', firstArg);
  } catch (_) {}

  /* ------------------------------------------------------------- network -- */
  function endpoint(opts, arg2) {
    if (typeof opts === 'number') return (arg2 && typeof arg2 === 'string' ? arg2 : 'localhost') + ':' + opts;
    if (typeof opts === 'string') return opts;                       // unix socket or url
    if (opts && typeof opts === 'object') {
      if (opts.href) return opts.href;
      var host = opts.host || opts.hostname || opts.path || 'unknown';
      return opts.port ? host + ':' + opts.port : String(host);
    }
    return 'unknown';
  }

  try {
    var net = require('net');
    wrap(net, 'connect', 'net.connect', endpoint);
    wrap(net, 'createConnection', 'net.connect', endpoint);
    if (net.Socket && net.Socket.prototype) {
      wrap(net.Socket.prototype, 'connect', 'net.connect', endpoint);
    }
  } catch (_) {}

  try {
    var tls = require('tls');
    wrap(tls, 'connect', 'net.connect', function (o, a2) { return 'tls:' + endpoint(o, a2); });
  } catch (_) {}

  ['http', 'https'].forEach(function (mod) {
    try {
      var m = require(mod);
      var describe = function (o, a2) {
        var e = typeof o === 'string' ? o : endpoint(o, a2);
        return mod + '://' + String(e).replace(/^https?:\/\//, '');
      };
      wrap(m, 'request', 'net.connect', describe);
      wrap(m, 'get', 'net.connect', describe);
    } catch (_) {}
  });

  try {
    var dns = require('dns');
    wrap(dns, 'lookup', 'net.dns', function (h) { return str(h); });
    if (dns.promises) wrap(dns.promises, 'lookup', 'net.dns', function (h) { return str(h); });
    ['resolve', 'resolve4', 'resolveTxt'].forEach(function (n) {
      wrap(dns, n, 'net.dns', function (h) { return str(h); });
    });
  } catch (_) {}

  // fetch() reaches the network through undici, which uses net/tls above, but the
  // URL is only visible here.
  if (typeof globalThis.fetch === 'function') {
    var realFetch = globalThis.fetch;
    globalThis.fetch = function (input) {
      try { emit('net.connect', 'fetch:' + str(input && input.url ? input.url : input)); } catch (_) {}
      return realFetch.apply(this, arguments);
    };
  }

  /* ------------------------------------------------- outbound taint check -- */
  // Canaries are checked at write() rather than on the wire: at this point the
  // bytes are still plaintext, so TLS does not hide an exfiltration attempt.
  var canaries = (process.env.SKILLCHECK_CANARIES || '').split(',').filter(Boolean);
  // Remove the list before server code runs, so it cannot enumerate the decoys
  // it is being tested with. Children of the server still inherit the trace
  // path but not the list: their writes are traced, not taint-checked.
  try { delete process.env.SKILLCHECK_CANARIES; } catch (_) {}

  if (canaries.length > 0) {
    var scan = function (chunk, where) {
      try {
        if (!chunk) return;
        var text = typeof chunk === 'string' ? chunk
          : Buffer.isBuffer(chunk) ? chunk.toString('utf8')
          : chunk instanceof Uint8Array ? Buffer.from(chunk).toString('utf8')
          : '';
        if (!text) return;
        for (var i = 0; i < canaries.length; i++) {
          if (text.indexOf(canaries[i]) !== -1) {
            emit('exfil.canary', canaries[i] + ' -> ' + where);
          }
        }
      } catch (_) {}
    };

    var socketTarget = function (sock) {
      try {
        return (sock._host || sock.remoteAddress || sock.host || 'unknown') +
          (sock.remotePort ? ':' + sock.remotePort : '');
      } catch (_) { return 'unknown'; }
    };

    try {
      var netMod = require('net');
      if (netMod.Socket && netMod.Socket.prototype) {
        // TLSSocket inherits write from net.Socket, so this covers https too.
        var realWrite = netMod.Socket.prototype.write;
        netMod.Socket.prototype.write = function (chunk) {
          scan(chunk, socketTarget(this));
          return realWrite.apply(this, arguments);
        };
      }
    } catch (_) {}

    try {
      var httpMod = require('http');
      if (httpMod.ClientRequest && httpMod.ClientRequest.prototype) {
        ['write', 'end'].forEach(function (name) {
          var real = httpMod.ClientRequest.prototype[name];
          if (typeof real !== 'function') return;
          httpMod.ClientRequest.prototype[name] = function (chunk) {
            var host = (this.getHeader && this.getHeader('host')) || this.host || 'unknown';
            scan(chunk, String(host) + (this.path || ''));
            return real.apply(this, arguments);
          };
        });
      }
    } catch (_) {}

    if (typeof globalThis.fetch === 'function') {
      var taintedFetch = globalThis.fetch;
      globalThis.fetch = function (input, init) {
        try {
          var url = str(input && input.url ? input.url : input);
          if (init && init.body) scan(init.body, url);
          scan(url, url);
        } catch (_) {}
        return taintedFetch.apply(this, arguments);
      };
    }
  }

  /* ----------------------------------------------------------- processes -- */
  try {
    var cp = require('child_process');
    ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'].forEach(function (name) {
      wrap(cp, name, 'process.exec', function (cmd, args) {
        var a = Array.isArray(args) ? ' ' + args.join(' ') : '';
        return (str(cmd) + a).slice(0, 300);
      });
    });
  } catch (_) {}

  /* ----------------------------------------------------- environment vars -- */
  var SECRETISH = /SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL|SESSION|COOKIE|AUTH/i;
  try {
    var realEnv = process.env;
    var proxied = new Proxy(realEnv, {
      get: function (target, prop) {
        if (typeof prop === 'string' && SECRETISH.test(prop)) emit('env.read', prop);
        return target[prop];
      },
      ownKeys: function (target) {
        // Enumerating the whole environment is how a harvester reads everything
        // without naming anything.
        emit('env.read', '<enumerate>');
        return Reflect.ownKeys(target);
      },
    });
    Object.defineProperty(process, 'env', { value: proxied, configurable: true, writable: true });
  } catch (_) {}

  emit('probe.ready', String(process.pid));
})();
