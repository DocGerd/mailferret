# V2: GreenMail for IMAP integration tests

Spike run against `greenmail/standalone:2.1.15` (Docker, Linux). The TLS/auth checks are listed at the end; the other findings used ad-hoc IMAP commands. Sources: the GreenMail docs and CapabilityCommand.java and ImapConstants.java at tag `release-2.1.15`.

## Findings
- Ports with `-Dgreenmail.setup.test.all`: IMAP 3143, IMAPS 3993, API 8080 (also SMTP 3025, SMTPS 3465, POP3 3110, POP3S 3995).
- STARTTLS: VERIFIED not supported. CAPABILITY on 3143 omits it and `STARTTLS` gets `BAD Invalid command.` (server log: `Command 'STARTTLS' not valid`).
- CAPABILITY (identical on 3143 and 3993): `IMAP4rev1 LITERAL+ UIDPLUS SORT IDLE MOVE SASL-IR AUTH=XOAUTH2 QUOTA`. No CONDSTORE, ESEARCH, THREAD, SPECIAL-USE or NAMESPACE. `AUTH=XOAUTH2` is advertised, not `AUTH=PLAIN`; LOGIN works.
- ESEARCH: VERIFIED absent. `SEARCH RETURN (COUNT) ALL` gets `BAD Search command not supported`.
- CONDSTORE: VERIFIED absent. `SELECT INBOX (CONDSTORE)` gets `BAD Expected end-of-line ...`.
- Users: the default `GREENMAIL_OPTS` contains `-Dgreenmail.auth.disabled`; overriding `GREENMAIL_OPTS` replaces the whole string, so omitting it enables auth. VERIFIED: with auth enabled a wrong password and an unknown user both get `NO LOGIN failed`; no account is auto-created. `GREENMAIL_ADDITIONAL_OPTS` (2.1.9+) appends and cannot remove `auth.disabled` (docs, not run).
- User format is `login:password@domain`. REFUTED: the password is `pw-a`, not `pw-a@example.com`. Login names:

  | `-Dgreenmail.users.login=email` | `alice@example.com` / `pw-a` | `alice` / `pw-a` | any user with `pw-a@example.com` |
  |---|---|---|---|
  | set | OK | NO | NO |
  | unset | NO | OK | NO |

  Tests use `login=email` and the address as login name.
- TLS keystore: VERIFIED. PKCS12 with `-Dgreenmail.tls.keystore.file`, `.password` and `-Dgreenmail.tls.key.password` (same throwaway value, shown as `<store-pw>`) loads: no keystore error in the container log and IMAPS presents the mounted `CN=localhost` cert. The container user can read a keystore mounted `:ro` when the file is world-readable (mode 644); the key itself is not needed after packing. The docs name no truststore option; none is needed.
- Verified TLS: with `certs/ca.pem` as CA and hostname `localhost`, `openssl s_client` reports `Verification: OK`; without it, `self-signed certificate` and a failed handshake. `imaplib` with `ssl.create_default_context(cafile=...)` (hostname check on) connects and logs in OK to both `localhost` and `127.0.0.1` (the IP SAN works); with no `cafile` both fail with `SSLCertVerificationError: CERTIFICATE_VERIFY_FAILED ... self-signed certificate`.
- AUTHENTICATE PLAIN (forced, not advertised): REFUTED. Without SASL-IR, `AUTHENTICATE PLAIN` gets `NO ... Unsupported authentication mechanism 'PLAIN'`; with an initial response it gets `BAD Expected end-of-line ...`. Neither authenticates.
- Plus addressing: VERIFIED. APPEND stores the message untouched; `To: user+tag@example.com` comes back exactly via `FETCH BODY.PEEK[HEADER.FIELDS (TO)]`. APPEND takes no recipients, so there is no delivery rewriting. `-Dgreenmail.sieve.ignore.detail` only affects SMTP delivery.
- Search semantics (GreenMail-specific): `SEARCH TO user+tag@example.com` matches (address equality); `TO user` and `TO "user+tag"` match nothing; `HEADER To user+tag` matches (substring). Tests for partial address matching must use `HEADER`, not `TO`.
- Mailbox: APPEND to INBOX lands in INBOX of the logged-in account only; the other account's INBOX stays empty. `LIST` returns only `INBOX` (hierarchy delimiter `.`), no other folders by default.
- Peek: VERIFIED. `EXAMINE` then `FETCH BODY.PEEK[]` leaves FLAGS at `(\Recent)`, still without `\Seen` after re-examine. An APPEND without flags yields no `\Seen`.

## Decisions
- GreenMail covers IMAPS, LOGIN auth, flags and `\Seen` unchanged, two accounts, login failure and `ca_file`.
- T-03 `test_login_redaction`: the AUTHENTICATE PLAIN leg runs on the D0 fake server (GreenMail rejects PLAIN); the LOGIN leg runs on GreenMail. SECURITY T-03 needs a follow-up edit (not in this PR), tracked in issue #7.
- D4 connects to host `localhost` (both forms verify; `localhost` matches the cert CN).
- STARTTLS, CONDSTORE, ESEARCH, THREAD and SPECIAL-USE positive paths are tested only on the D0 fake server (T-07). D4 also uses plaintext port 3143 as a real-server "STARTTLS not advertised" case (hard error, no LOGIN sent). The T-07 GreenMail check (fails without `ca_file`, passes with it) is confirmed with `imaplib`.
- Override `GREENMAIL_OPTS` in full, without `auth.disabled`.
- Generate a throwaway cert at test time (SAN `localhost` and `127.0.0.1`), pack it into PKCS12, mount it read-only, pass the cert PEM as `ca_file`. Generate into a `mktemp -d` outside the work tree. The key is throwaway (trusted only via the test's `ca_file`, valid 2 days) and the PKCS12 is world-readable (644 in a 755 dir) so the container user can read it; acceptable on a dev/CI host. Never commit key material.
- Seed mail by APPEND. Do not rely on SMTP delivery.
- Pin the image `greenmail/standalone:2.1.15`; D4 adds the digest (see D4 requirements).

## D4 requirements
- Run the `ca_file` fails-without/passes-with check through mailferret's own TLS context builder (system store plus `load_verify_locations`, TLS 1.2 minimum), not `ssl.create_default_context(cafile=...)`, which the spike used and skips the system store.
- Add a control test that `SELECT` plus `FETCH BODY[]` sets `\Seen` on GreenMail, so `test_no_mutation` can fail. It runs on a raw `imapclient` connection inside the test, never through `ReadOnlySession` or any guard bypass in `src/`, with its own message or account outside the `test_no_mutation` before/after snapshot.
- Assert the port 3143 "STARTTLS not advertised, no LOGIN sent" case with a client-side wire recorder (or the GreenMail log), and assert the credential backend `get` is never called.
- Pin the image by digest (`greenmail/standalone:2.1.15@sha256:...`) and record it beside the vetted version.
- Gitignore `tests/integration/certs/`.
- Wait for readiness before connecting (poll the IMAPS port); `docker compose up -d` returns before the JVM listens (not timed here).

## Compose (as run)
    services:
      greenmail:
        image: greenmail/standalone:2.1.15
        environment:
          GREENMAIL_OPTS: >-
            -Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0
            -Dgreenmail.users=alice:pw-a@example.com,bob:pw-b@example.com
            -Dgreenmail.users.login=email
            -Dgreenmail.tls.keystore.file=/certs/greenmail.p12
            -Dgreenmail.tls.keystore.password=<store-pw>
            -Dgreenmail.tls.key.password=<store-pw>
        ports: ["127.0.0.1:3143:3143", "127.0.0.1:3993:3993"]
        volumes: ["${CERTS_DIR}:/certs:ro"]

Test logins: `alice@example.com` and `bob@example.com`; the password is the part of `users=login:password@domain` before the `@`, here `pw-a` and `pw-b`.

## Commands (as run)
Cert (the self-signed cert is also the CA):

    export CERTS_DIR=$(mktemp -d)   # outside the work tree; mounted as /certs
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CERTS_DIR/k.pem" -out "$CERTS_DIR/ca.pem" -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1
    openssl pkcs12 -export -in "$CERTS_DIR/ca.pem" -inkey "$CERTS_DIR/k.pem" -out "$CERTS_DIR/greenmail.p12" -passout pass:<store-pw>
    rm "$CERTS_DIR/k.pem"; chmod 644 "$CERTS_DIR/greenmail.p12" "$CERTS_DIR/ca.pem"; chmod 755 "$CERTS_DIR"
    docker compose up -d

Checks: `IMAP4_SSL` to `localhost` and `127.0.0.1` with and without `cafile`; forced `AUTHENTICATE PLAIN` over IMAPS with and without an initial response; `printf 'a CAPABILITY\r\nb STARTTLS\r\nc LOGOUT\r\n' | nc -w3 127.0.0.1 3143`; `openssl s_client -connect 127.0.0.1:3993 -CAfile "$CERTS_DIR/ca.pem" -verify_return_error -verify_hostname localhost </dev/null`; `imaplib.IMAP4_SSL('127.0.0.1', 3993, ssl_context=ssl.create_default_context(cafile=os.environ['CERTS_DIR'] + '/ca.pem'))` then `login('alice@example.com', 'pw-a')`. Teardown: `docker compose down -v`.
Note: `imaplib` has no ESEARCH/CONDSTORE helpers; send them with `_simple_command`.
