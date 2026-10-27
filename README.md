# Grange Fencing Secure Session

Hardened PHP session handling for applications that need secure session cookies,
CSRF tokens, session integrity and expiry checks, periodic session-ID rotation,
and secure logout.

## Requirements

- PHP 8.3 or later
- PHP `ctype` extension

Install with Composer in an application that has access to this package:

```sh
composer require grange-fencing/secure-session
```

Composer provides the `GrangeFencing\SecureSession\SecureSession` class through
its PSR-4 autoloader.

## Configuration

Set configuration in `$_ENV` before calling `SecureSession::start()`. Integer
settings must be positive decimal integers; unset or invalid values use the
defaults below. The session name must start with a letter and contain only
letters, digits, or underscores, with a maximum length of 64 characters.

| `$_ENV` key | Default | Description |
| --- | ---: | --- |
| `SECURE_SESSION_NAME` | `PHPSESSID` | PHP session cookie name |
| `SECURE_SESSION_INACTIVITY_TIMEOUT_SECONDS` | `1800` | Maximum idle time |
| `SECURE_SESSION_ABSOLUTE_TIMEOUT_SECONDS` | `28800` | Maximum session age |
| `SECURE_SESSION_ROTATION_INTERVAL_SECONDS` | `300` | Interval between periodic session-ID rotations |
| `SECURE_SESSION_ROTATION_GRACE_SECONDS` | `10` | How long requests carrying a superseded ID remain valid |

Populate `$_ENV` explicitly if the application obtains configuration through
another mechanism. These settings are read when the session is configured, so
set them before the first session start.

## Usage

Start and validate the session before using its values. Do this before sending
response output, because PHP may need to send session and cookie headers.

```php
use GrangeFencing\SecureSession\SecureSession;

SecureSession::start();

if (SecureSession::isNotValid()) {
    http_response_code(401);
    exit;
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $csrfToken = $_POST["csrf_token"] ?? null;
    if (!is_string($csrfToken) || !SecureSession::validateCsrfToken($csrfToken)) {
        http_response_code(403);
        exit;
    }

    // Process the request only after validating its CSRF token.
}
```

Render the token into a form, escaping it for the output context:

```php
<input
    type="hidden"
    name="csrf_token"
    value="<?= htmlspecialchars(SecureSession::getCsrfToken(), ENT_QUOTES, "UTF-8") ?>"
>
```

After verifying credentials, record the authenticated state and rotate the ID
to prevent session fixation:

```php
SecureSession::setValues([
    "loggedIn" => true,
    "userId" => $userId,
]);
SecureSession::regenerate();
```

On authenticated requests, call `start()` and `isNotValid()` before making
authorization decisions. Alternatively, `isValidLoggedInSession()` starts the
session and performs validity checks before confirming that `loggedIn` is
explicitly `true`.

On logout, call `SecureSession::destroy()` to clear the session, revoke its
related session ID when applicable, and expire the session cookie.

## Public API

Call `start()` before using the CSRF-token or session-value methods; they operate
on the active PHP session.

| Method | Description |
| --- | --- |
| `start(): void` | Configures and starts the session, then initializes or backfills security metadata. |
| `isNotValid(): bool` | Checks initialization, expiry, fingerprint, and rotation state. Returns `true` when invalid; call after `start()`. |
| `isValidLoggedInSession(): bool` | Starts the session and returns whether it passes validation and has `loggedIn === true`. |
| `getCsrfToken(): string` | Gets the current session's CSRF token; call after `start()`. |
| `validateCsrfToken(string $token): bool` | Compares a submitted token with the session token using a timing-safe comparison. |
| `regenerate(): void` | Immediately rotates the session ID; use after login or another privilege change. |
| `destroy(bool $expireCookie = true): void` | Destroys the active session and, by default, expires the cookie and revokes its related ID. |
| `setValue(string $key, mixed $value): void` | Stores one session value. |
| `setValues(array $keyedValues): void` | Stores multiple session values. |
| `getValue(string $key, mixed $default = "__UNDEFINED__"): mixed` | Reads a session value, optionally returning a default if absent. |
| `isSet(string $key): bool` | Checks whether a session value is set. |

## Security behavior and operational notes

- Session cookies are HttpOnly and SameSite=Lax, use cookie-only transport, and
  have strict mode enabled; URL-based session IDs are disabled.
- The Secure cookie flag is enabled when PHP sees HTTPS or server port 443.
  Applications behind TLS-terminating proxies should ensure the PHP request
  environment reflects HTTPS appropriately.
- The request fingerprint is a SHA-256 hash of the user-agent string. It is an
  additional consistency check, not an authentication factor; changes to the
  user-agent between requests invalidate the session.
- Expired, fingerprint-mismatched, or otherwise invalid sessions must not be
  treated as authenticated. Check `isNotValid()` before authorization checks.
- Periodic rotation keeps the prior session briefly for parallel in-flight
  requests. This grace period is not intended for privilege changes; use
  `regenerate()` for those.
- The library does not authenticate users or authorize application actions.
  Applications remain responsible for credential verification, access control,
  output encoding, and appropriate cache behavior for sensitive responses.
