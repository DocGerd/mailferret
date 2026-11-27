# V3: headless credential behaviour (WSL/Linux)

Spike V3 (PLAN V3; A§10 item 7; T-17). Checks ran on one Linux/WSL2 machine in throwaway dirs (`$T` = `mktemp -d`; own `GNUPGHOME` and `PASSWORD_STORE_DIR`, never the user's keyring or store). Every number below is one machine, one GnuPG build; "n runs" counts repeats in one session.

Versions: GnuPG 2.4.4 (pinentry-curses 1.2.1 only), pass 1.7.4, Python 3.12.3, keyring 25.7.0, SecretStorage 3.5.0, jeepney 0.9.0. Only `C`, `C.utf8` and `POSIX` locales are installed, and no gnupg message catalogs.

`pass` wrapper facts (read from the script, then observed): `set -o pipefail`; gpg options `--quiet --yes --compress-algo=none --no-encrypt-to`, plus `--batch --use-agent` when `gpg2` is on PATH or `GPG_AGENT_INFO` is set (neither here, so plain `gpg`; the `gpg2` branch is covered once, see E1); `PASSWORD_STORE_GPG_OPTS` is word-split in front of those; it exports `GPG_TTY="${GPG_TTY:-$(tty)}"`, which is the literal `not a tty` when there is no tty.

## Verdicts

| Check | Claim | Verdict | Observed |
|---|---|---|---|
| E1 `pass show`, `--pinentry-mode=error`, cold agent | fails fast, no prompt, no hang | VERIFIED (pass) | rc=2, 16/21/28 ms (3 runs), stdout empty |
| E1 same, direct `gpg -d` | same | VERIFIED | rc=2, 11 ms (1 run); identical status lines |
| E2 default pinentry, no tty | does not hang | NO HANG WITHOUT A TTY | rc=2, ~1.0 s; not run with a real tty |
| E3 warm cache + error mode, `pass show` | still decrypts | VERIFIED (pass) | rc=0, ~415 ms, secret on stdout (2 runs) |
| E3x expired cache (`default-cache-ttl 1`, `max-cache-ttl 1`, unlock, sleep 6 s), `pass show` | fails like cold | VERIFIED (pass) | immediately after unlock rc=0 417 ms; after sleep rc=2 16 ms, same status lines as cold (1 run each; also direct gpg 9 ms, `env -i` 18 ms, `LC_ALL=C` 14 ms) |
| E4 same-session grandchild holds pipes | `killpg` frees the readers | VERIFIED for same-session descendants | see E4 |
| E4s descendant calls `setsid` | `killpg` frees the readers | REFUTED | see E4 |
| E5 no session bus | fast typed failure | VERIFIED | see E5/E6 |
| E6 dead bus (missing socket) | fast typed failure | PARTLY REFUTED (raw `FileNotFoundError`) | see E5/E6 |
| E6 mute bus | `keyring` is bounded | NOT SHOWN TO BE BOUNDED (single observation) | see E5/E6 |
| E7 `env -i`, `pass show` | no dependence on DISPLAY, XDG_RUNTIME_DIR, bus | VERIFIED (pass, cold and warm) | cold rc=2 20 ms; warm rc=0 408 ms |

Not run: `pass` with `GPG_AGENT_INFO` set (the other trigger of the `--batch --use-agent` branch; only the `gpg2`-on-PATH trigger was run), warm and expired cache on the `gpg2` branch; Secret Service bus discovery without `DBUS_SESSION_BUS_ADDRESS` (e.g. `$XDG_RUNTIME_DIR/bus`; not tested, see V3-4); default pinentry with a real tty (a prompt would block; outside headless scope); a client- or `wsl.exe`-launched process (E7 used `env -i` only); a bus that authenticates and then never replies (needs a fake D-Bus server); stderr under a non-English locale (none installed, no catalogs); a retained repro for the mute-bus keyring hang (keyring is not installed in the current environment).

### E1/E2/E3/E7 (pass and gpg)
`PASSWORD_STORE_GPG_OPTS="--pinentry-mode=error --status-fd=2"`; script in appendix A.1.
- Locked (cold or expired), `pass show` and direct `gpg`: rc=2, stdout empty, stderr `gpg: public key decryption failed: No pinentry`, `gpg: decryption failed: No pinentry` (`gpg` may also print `encrypted with ...` lines). Status lines: `[GNUPG:] NO_SECKEY ...`, `[GNUPG:] ERROR pkdecrypt_failed 67108949`, `[GNUPG:] DECRYPTION_FAILED`, `[GNUPG:] FAILURE gpg-exit 33554433`.
- `67108949` = source 4 (gpg-agent), code 85 (`GPG_ERR_NO_PIN_ENTRY`). `NO_SECKEY` and `DECRYPTION_FAILED` also appear, so neither is a lock signal.
- Cache expiry: after `default-cache-ttl 1` / `max-cache-ttl 1` and a 6 s sleep the cache was gone (rc=2, status identical to cold).
- Status channel through `pass`: `--status-fd=3` with fd 3 redirected to a file, and `--status-file=<path>`, both deliver `ERROR pkdecrypt_failed 67108949` with stderr carrying only the two `gpg:` lines (1 run each).
- Default pinentry, no tty, via `pass` (`setsid -w`, `PASSWORD_STORE_GPG_OPTS=--status-fd=2`): rc=2, ~1.0 s, `ERROR pkdecrypt_failed 83918929` (source 5 pinentry, code 32849), stderr `No such file or directory`, with and without `DISPLAY`. Cause: `pass` exported `GPG_TTY="not a tty"`; the same variable set by hand gives the same result. Direct `gpg` with no `GPG_TTY` gives `83918950` (code 32870) and `Inappropriate ioctl for device`. So the default-pinentry failure text and code depend on how gpg is launched.
- `gpg2` branch (throwaway `PATH` dir with a `gpg2` symlink to `gpg`, cold agent, `--pinentry-mode=error --status-fd=2`): rc=2, 12 ms, stdout empty, same status lines including `ERROR pkdecrypt_failed 67108949` (1 run).
- Locale: no non-English locale is installed and there are no gnupg catalogs, so translated stderr was not observed. `LC_ALL=C` stderr is identical to the ambient-locale text above.
- `pass show` missing entry: rc=1, stderr `Error: test/nope is not in the password store.` (1 run).

### E4 subprocess
Script in appendix A.2.
- `sh -c 'echo x; (sleep 30 &); exit 0'` (same session, `start_new_session=True`): child exits at 0.3 s rc 0, readers stay blocked on the grandchild; `os.killpg(pid, SIGKILL)` ends both readers (3 of 3 runs earlier; 1 run with the A.2 shape).
- `subprocess.run(..., capture_output=True, timeout=3)` with that command: always `TimeoutExpired`, 3.0 s in 6 of 6 runs (an earlier 0.5 s elapsed was not reproduced); no result is returned, the partial stdout is only on the exception, and the grandchild lives on.
- E4s: a descendant that calls `os.setsid()` and inherits the pipes leaves the group: `killpg` then raises `ProcessLookupError` (group empty), both readers stay blocked, and a plain unbounded join hangs (outer `timeout` rc=124). With daemon readers on raw fds, a stop flag, joins bounded to the deadline plus 2 x 0.2 s, and the parent's pipe files closed with `close()`, the call returned after 1.4 s for a 1.0 s deadline, readers still blocked, escaped process alive in its own session until killed by pid (1 run).
- An on-demand gpg-agent started cold under pipes: readers hit EOF in 0.02 s, so it did not hold the pipes; it runs in its own session (`sid == pid`), so `killpg` would not reach it either (1 run).

### E5/E6 keyring and Secret Service (isolated env, `env -i`; earlier session, not re-run)
- No `DBUS_SESSION_BUS_ADDRESS`: `keyring.get_keyring()` is `keyring.backends.fail.Keyring`; `get_password` raises `NoKeyringError`, 0.1 s. `secretstorage.dbus_init()` raises `SecretServiceNotAvailableException`, <0.1 s.
- Bus address set, socket missing: `dbus_init()` raises raw `FileNotFoundError` (0.0 s); `keyring` falls back to the fail backend / `NoKeyringError`, 0.04 s.
- Socket that accepts and never answers: `dbus_init()` raises raw `TimeoutError: Did not authenticate in 1.0 seconds` (1.1 s). `keyring.get_keyring()` on the same kind of bus did not return in 15 s (`timeout` rc=124, nothing printed). Single observation, no retained repro, cause not isolated; treat as "keyring may not be bounded", not as a measured rate.

## Decisions

Numbering is local to this note (V3-n); the owning PLAN task is named on each.

- V3-1 (B5, `command` backend). `Popen(shell=False, stdin=DEVNULL, pipes, close_fds, start_new_session=True, env=minimal)`, daemon reader threads on raw fds with a stop flag, `os.killpg(SIGKILL)` at the L-14 deadline, joins bounded. The return time must not depend on the readers ending: descendants that `setsid` escape `killpg` and may keep the pipes (E4s). Add a fake command that runs `setsid` while holding stdout to the B5 test list. `subprocess.run(timeout)` is unusable (E4). Result: if the deadline kills the process, or any reader is not at EOF at the return, the call returns `timeout` and discards both buffers; partial stdout is never used as a secret (it would count as a failed login, T-16). Readers enforce L-22 on stdout while reading: on a breach they kill the group and return `limit_exceeded`. Stderr has a fixed internal cap.
- V3-2 (B5, `command` and `pass` recipe). Classify `locked` on the status code, not on text: non-zero exit and `[GNUPG:] ERROR pkdecrypt_failed <n>` with source 4 and code 85 (`n == 67108949`). The recipe must carry `--pinentry-mode=error` and a status channel separate from stderr. `close_fds=True` closes fd 3 in the child, so B5 passes the status fd via `pass_fds`, reads it with its own daemon reader under the L-14 deadline with a byte cap, and closes it at the bounded return like the other pipes (it can be held by a descendant, E4/E4s). Alternative: `--status-file=<path>` in a private 0600 path, removed after the call. B5 test: a locked store reads `locked` through the real spawn path (not a shell-redirected fd). Any other `pkdecrypt_failed` code, including the pinentry-source codes above, or no status line is `error`. Stderr text (`No pinentry`) may be matched only when the child ran under `LC_ALL=C`, as confirmation. Stderr bytes may contain the secret and never leave the classifier: not logged, not returned, not in exceptions. `not_found` for `pass` is rc=1 with `is not in the password store` (pass's own untranslated message), matched under `LC_ALL=C`.
- V3-3 (B5, `pass` recipe). Keep `--pinentry-mode=error`: a locked store fails in ~0.02 s and a warm cache still decrypts. The A§10 item 7 TTL fallback stays documentation only; it is not shown to be needed on GnuPG 2.4.4 with `pass` 1.7.4 and plain `gpg`. The `gpg2`-on-PATH branch was run cold only; `GPG_AGENT_INFO` and the warm/expired cases on that branch are not run.
- V3-4 (B4, keyring backend). Pre-check `DBUS_SESSION_BUS_ADDRESS` per address type, then probe in a subprocess with a hard timeout and `killpg`; never call `keyring.get_password` in-process on the serve path.
  - Unset: `unavailable`, no D-Bus call. No fallback discovery (such as `$XDG_RUNTIME_DIR/bus`) is attempted and none was tested; `keyring` users must export the variable.
  - The value is a `;`-separated list: parse every entry. Accept only transport exactly `unix` with exactly one of `path`/`abstract` (plus `guid`). Anything else is `unavailable`: `unixexec:` (runs a program), `autolaunch:` (spawns `dbus-launch`), `nonce-tcp:`, `tcp:`, `launchd:`, and the listen-only keys `tmpdir`/`dir`/`runtime`. The only network connection mailferret makes is IMAP.
  - Hand the probe only the accepted entries.
  - `unix:path=<p>`: `unavailable` if `<p>` does not exist, else probe.
  - `unix:abstract=...`: no path to check, go to the probe.
- V3-5 (B4, `detect.py`). Treat raw `FileNotFoundError`, `ConnectionError` and `TimeoutError` from `dbus_init` as `CredentialBackendUnavailable`.

## Impact on A§2 / A§10 / T-17

- A§10 item 7: confirmed at the `pass` + gpg level for GnuPG 2.4.4 / pass 1.7.4, cold and expired agent, `env -i`. A client- or `wsl.exe`-launched process was not run.
- T-17: to be verified (issue #7). The `command` evidence is for same-session descendants plus the bounded-return shape in V3-1; the keyring path has no verified bound.
- A§2.1: to be verified (issue #7). E6 (single observation) does not show "keyring is bounded"; the subprocess probe is justified without a contradiction, and a retained mute-bus repro is needed before any keyring bound is claimed as tested. V3-4 changes the keyring path, so this spike triggers the architecture update before B4 starts (PLAN §2a rule on contradicting spikes).

## Follow-up design edits (issue #7)

Not edited here (ARCHITECTURE, SECURITY, PLAN are out of scope for this PR).
- A§2.1: replace the in-process `keyring.get_password` with a subprocess keyring probe (V3-4), with the per-type bus-address pre-check.
- T-17: extend to the keyring path, or add a new T-nn, with an L-nn bound (reuse L-14/L-22 or add one) for the probe; state the setsid limit and the bounded-return requirement (V3-1).
- PLAN: add V3 to B4's dependencies (B4 currently lists F0 and B3).
- A§2.1 `command`: the `pass` recipe gains a separate status channel via `pass_fds` and the fail-closed return (V3-1, V3-2); line 47 shows only `--pinentry-mode=error`.
- T-02/T-03: cover the secret crossing a pipe from the probe subprocess: output cap, minimal env, stderr never logged.
- Both items above and the mute-bus repro are tracked in #7.

## Appendix: repro scripts

Run with `GNUPGHOME`, `PASSWORD_STORE_DIR` and `T` pointing into one `mktemp -d`; check them before every call. Wrap each command in `timeout -k 2 <n> </dev/null`.

### A.1 pass and gpg (E1, E3, E3x, E7)
```sh
PW=$(head -c12 /dev/urandom | base64)
printf 'allow-loopback-pinentry\ndefault-cache-ttl %s\nmax-cache-ttl %s\n' 600 600 >"$GNUPGHOME/gpg-agent.conf"
gpg --batch --pinentry-mode loopback --passphrase-fd 3 --quick-gen-key user@example.com default default never 3<<<"$PW"
pass init user@example.com; printf 'x\n' | pass insert -e test/entry
conf() { printf 'allow-loopback-pinentry\ndefault-cache-ttl %s\nmax-cache-ttl %s\n' "$1" "$1" >"$GNUPGHOME/gpg-agent.conf"; gpgconf --kill gpg-agent; }
unlock() { gpg --batch --pinentry-mode loopback --passphrase-fd 3 -d "$PASSWORD_STORE_DIR/test/entry.gpg" 3<<<"$PW" >/dev/null; }
export PASSWORD_STORE_GPG_OPTS="--pinentry-mode=error --status-fd=2"
conf 600; gpgconf --kill gpg-agent; time pass show test/entry; echo rc=$?     # cold
unlock; pass show test/entry                                                  # warm
conf 1; unlock; sleep 6; time pass show test/entry; echo rc=$?                # expired
env -i PATH="$PATH" GNUPGHOME="$GNUPGHOME" PASSWORD_STORE_DIR="$PASSWORD_STORE_DIR" \
  PASSWORD_STORE_GPG_OPTS="$PASSWORD_STORE_GPG_OPTS" pass show test/entry     # E7
```

### A.2 E4 / E4s (python3 -I)
```python
import os, signal, subprocess, sys, threading, time
DEADLINE = 1.0

def run(argv):
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, close_fds=True, start_new_session=True)
    stop, bufs = threading.Event(), {"out": bytearray(), "err": bytearray()}
    def reader(name, fd):
        while not stop.is_set():
            b = os.read(fd, 65536)
            if not b:
                return
            bufs[name] += b
    ts = [threading.Thread(target=reader, args=(n, f.fileno()), daemon=True)
          for n, f in (("out", p.stdout), ("err", p.stderr))]
    for t in ts: t.start()
    t0 = time.monotonic()
    try: p.wait(timeout=DEADLINE)
    except subprocess.TimeoutExpired: pass
    for t in ts: t.join(max(0.0, t0 + DEADLINE - time.monotonic()))
    if p.poll() is None or any(t.is_alive() for t in ts):
        try: os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        for t in ts: t.join(0.2)
    stop.set()
    for f in (p.stdout, p.stderr):
        f.close()
    return round(time.monotonic() - t0, 2), p.poll(), [t.is_alive() for t in ts]

SAME = ["sh", "-c", "echo x; (sleep 30 &); exit 0"]
SETSID = [sys.executable, "-I", "-c",
          "import os,sys,time\n"
          "if os.fork()==0:\n"
          "    os.setsid(); open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(30); os._exit(0)\n"
          "print('x', flush=True); os._exit(0)", os.environ["T"] + "/escaped.pid"]
print(run(SAME))     # killpg frees the readers
print(run(SETSID))   # returns at deadline + joins; readers still alive; kill the pid in the file afterwards
```
Naive variant: after the `SETSID` child exits, `os.killpg` raises `ProcessLookupError` and an unbounded `join` on a reader never returns.

Cleanup: gpg-agent killed (`gpgconf --kill gpg-agent`, throwaway `GNUPGHOME`), escaped processes killed by pid, `$T` removed.
