# V3: headless credential behaviour (WSL/Linux)

Spike V3 (PLAN V3; A§10 item 7; T-17). Checks run on one Linux/WSL2 machine in throwaway dirs (`$T` = `mktemp -d`; own `GNUPGHOME`, never the user's keyring or store).

Versions: GnuPG 2.4.4 (pinentry-curses only), Python 3.12.3, keyring 25.7.0, SecretStorage 3.5.0, jeepney 0.9.0. `pass`: not installed, not run (apt package `pass`; `gnupg` and `pinentry-curses` were present).

## Verdicts

| Check | Verdict | Observed |
|---|---|---|
| E1 `--pinentry-mode=error`, cold agent | VERIFIED (gpg level) | rc=2, 0.009 s (3 runs), stdout empty |
| E2 default pinentry, no tty | REFUTED (no hang) | rc=2, ~1.0 s, fails fast |
| E3 warm cache + error mode | VERIFIED | rc=0, 0.56 s, secret printed |
| E4 grandchild holds pipes | VERIFIED | see below |
| E5 no session bus | VERIFIED | see below |
| E6 dead / mute bus | PARTLY REFUTED | see below |
| E7 `env -i` (no DISPLAY, XDG_RUNTIME_DIR, bus) | VERIFIED (gpg level) | rc=2, 0.009 s, same stderr as E1 |
| `pass show` wrapper (E1-E3, E7 via `pass`) | not run: tool missing | gpg-level equivalent run; `pass` only adds `-d` plus `PASSWORD_STORE_GPG_OPTS` word-splitting |

Not run: default pinentry with a real tty (a prompt would block; outside headless scope); a bus that authenticates and then never replies (needs a fake D-Bus server).

### E1/E2/E3/E7 (gpg)
Cold agent, `gpg -d --pinentry-mode=error f.gpg </dev/null`:
- rc=2 in 0.009 s (3 runs, agent killed before each); identical under `env -i`.
- Stderr patterns (sanitized): `gpg: public key decryption failed: No pinentry` and `gpg: decryption failed: No pinentry`. Status lines: `[GNUPG:] ERROR pkdecrypt_failed 67108949`, `[GNUPG:] DECRYPTION_FAILED`, `[GNUPG:] FAILURE gpg-exit 33554433`. `[GNUPG:] NO_SECKEY` also appears in the locked case, so `No secret key` is not a lock signal.
- Default pinentry, no tty (with and without `DISPLAY`): rc=2, ~1.0 s, `gpg: public key decryption failed: Inappropriate ioctl for device` and `gpg: decryption failed: Inappropriate ioctl for device`. No hang here; a tty or GUI session may prompt, so error mode is still required.
- Warm cache (unlocked via loopback): error mode returns rc=0 and the plaintext.
- Missing file: rc=2, `gpg: can't open '$T/x.gpg': No such file or directory`.

### E4 subprocess
`sh -c 'echo x; (sleep 30 &); exit 0'`:
- Child exits at 0.3 s with rc 0; both reader threads stay alive (grandchild holds the pipes). With `start_new_session=True`, `os.killpg(pid, SIGKILL)` ends both readers immediately (3 of 3 runs).
- `subprocess.run(..., capture_output=True, timeout=3)`: always `TimeoutExpired`, even though the child exited rc 0. Elapsed 3.0 s in most runs, 0.5 s in some (unexplained); output is lost and the grandchild is not killed. Same with `start_new_session=True`.

### E5/E6 keyring and Secret Service (isolated env, `env -i`)
- No `DBUS_SESSION_BUS_ADDRESS`: `keyring.get_keyring()` is `keyring.backends.fail.Keyring`; `get_password` raises `NoKeyringError: No recommended backend was available...`, 0.1 s. `secretstorage.dbus_init()` raises `SecretServiceNotAvailableException: Environment variable DBUS_SESSION_BUS_ADDRESS is unset`, <0.1 s.
- Bus address set, socket missing: `dbus_init()` raises raw `FileNotFoundError: [Errno 2] No such file or directory` (0.0 s), not `SecretServiceNotAvailableException`. `keyring` falls back to the fail backend / `NoKeyringError`, 0.04 s.
- Socket that accepts and never answers: `dbus_init()` raises raw `TimeoutError: Did not authenticate in 1.0 seconds` (jeepney auth timeout, 1.1 s). But `keyring.get_keyring()` on the same kind of bus did not return in 15 s (`timeout` rc=124, nothing printed). REFUTES "keyring is bounded".

## Decisions

- D1 (unchanged). `command` lookups: `Popen(shell=False, stdin=DEVNULL, pipes, close_fds, start_new_session=True, env=minimal)`, reader threads, `os.killpg(SIGKILL)` at the L-14 deadline, bounded joins. E4: killpg frees the readers; `subprocess.run(timeout)` is unusable (loses output, leaves the grandchild).
- D2 settled. Non-zero exit with stderr containing `No pinentry` or `Inappropriate ioctl for device` means `locked`. `No secret key` / `NO_SECKEY` is not a lock signal. Prefer `--status-fd` (`DECRYPTION_FAILED`) with the text match as confirmation. `not_found` for `pass` stays "is not in the password store" (unverified without `pass`). Never log stderr.
- D3 settled. Keep `--pinentry-mode=error` in the `pass` recipe: fails in ~0.01 s, warm cache still decrypts. The A§10 item 7 TTL fallback stays documentation only. Re-verify the `pass` wrapper where `pass` is installed.
- D4 settled, stricter. Unset `DBUS_SESSION_BUS_ADDRESS`, or a missing socket path: `unavailable` with no D-Bus call. Otherwise probe in a subprocess with a hard timeout (killpg); never call `keyring.get_password` in-process on the serve path, because keyring can hang on a mute bus although `dbus_init` itself times out at 1 s.
- D5 amended. `detect.py` must also treat raw `FileNotFoundError`, `ConnectionError` and `TimeoutError` from `dbus_init` as `CredentialBackendUnavailable`.

## Impact on A§2 / A§10 / T-17

- A§10 item 7: confirmed; the TTL fallback is not needed for GnuPG 2.4.4.
- T-17: confirmed for `command` (killpg design). The keyring hang means the bound must be a process-level kill; a thread cannot be killed.
- Earlier draft claim "`dbus_init` has no timeout" is wrong (jeepney auth times out at 1 s); the open-ended hang is elsewhere in the keyring path (cause not isolated).

Cleanup: throwaway gpg-agent killed with the throwaway `GNUPGHOME`, mute listeners killed, temp dirs removed.
