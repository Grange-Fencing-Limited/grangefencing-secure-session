<?php

    namespace GrangeFencing\SecureSession;

    use Random\RandomException;

    /**
     * Class SecureSession
     *
     * Manages hardened session handling, including strict session cookie configuration, CSRF token handling,
     * user-agent fingerprint validation, inactivity and absolute lifetime checks, periodic ID rotation,
     * and session destruction.
     *
     * Expected lifecycle (login example):
     * 1. Login page GET calls SecureSession::start() and renders SecureSession::getCsrfToken() in the form.
     * 2. Login POST calls SecureSession::start(), then SecureSession::isNotValid() and
     *    SecureSession::validateCsrfToken($postedToken). Reject the request if either check fails.
     * 3. After credential verification, write authentication flags/user identifiers to the session and call
     *    SecureSession::regenerate() to rotate the session ID on privilege change.
     * 4. Each authenticated request calls SecureSession::start() and SecureSession::isNotValid() before
     *    authorization checks; this enforces expiry, fingerprint consistency, and periodic ID rotation.
     * 5. Logout calls SecureSession::destroy() to clear state and expire the session cookie.
     *
     * Configuration is read from $_ENV (see the SECURE_SESSION_* variables), so the host application must
     * populate $_ENV before the first SecureSession::start(). Unset or invalid values use the defaults.
     * Methods that access session data generally require an active PHP session; call start() first.
     * isValidLoggedInSession() is an exception and starts the session itself.
     *
     * @version 1.2.0
     * @publishDate 2026-10-23
     */
    class SecureSession {

        private const string CSRF_TOKEN_KEY = "csrfToken";

        private const string ENV_SESSION_NAME               = "SECURE_SESSION_NAME";
        private const string ENV_INACTIVITY_TIMEOUT_SECONDS = "SECURE_SESSION_INACTIVITY_TIMEOUT_SECONDS";
        private const string ENV_ABSOLUTE_TIMEOUT_SECONDS   = "SECURE_SESSION_ABSOLUTE_TIMEOUT_SECONDS";
        private const string ENV_ROTATION_INTERVAL_SECONDS  = "SECURE_SESSION_ROTATION_INTERVAL_SECONDS";
        private const string ENV_ROTATION_GRACE_SECONDS     = "SECURE_SESSION_ROTATION_GRACE_SECONDS";
        private const string SUPERSEDED_AT_KEY              = "supersededAt";
        private const string SUPERSEDED_BY_KEY              = "supersededBy";
        private const string SUPERSEDED_FROM_KEY            = "supersededFrom";
        private const string REVOKED_KEY                    = "revoked";

        private const array DEFAULTS = [
            self::ENV_SESSION_NAME               => "PHPSESSID",
            self::ENV_INACTIVITY_TIMEOUT_SECONDS => 1800,
            self::ENV_ABSOLUTE_TIMEOUT_SECONDS   => 28800,
            self::ENV_ROTATION_INTERVAL_SECONDS  => 300,
            self::ENV_ROTATION_GRACE_SECONDS     => 10,
        ];

        /**
         * Reads a setting from the environment, falling back to its default when unset or invalid.
         *
         * Integer settings must be positive decimal strings. The session name must start with a letter and
         * contain only letters, digits and underscores, up to 64 characters. Configuration is read from $_ENV.
         *
         * @param string $name One of the ENV_* constants.
         *
         * @return string|int
         */
        private static function setting(string $name): string|int {

            $default = self::DEFAULTS[$name];

            $raw = $_ENV[$name] ?? null;
            if (!is_string($raw) || $raw === "") {
                return $default;
            }

            if (is_int($default)) {
                return ctype_digit($raw) && (int)$raw > 0 ? (int)$raw : $default;
            }

            return preg_match("/^[A-Za-z][A-Za-z0-9_]{0,63}$/", $raw) === 1 ? $raw : $default;

        }

        /**
         * Starts the session using secure cookie/session configuration when no session is active, then
         * initializes or backfills required security metadata.
         *
         * Configuration is applied only when PHP has no active session. Call before sending response output.
         *
         * @return void
         */
        public static function start(): void {

            if (session_status() == PHP_SESSION_NONE) {
                self::configureSessionOptions();
                session_start();
            }

            if (!self::isSet("initialized")) {
                self::initializeSession();

                return;
            }

            self::ensureSessionSecurityMetadata();

        }

        /**
         * Initializes a new session with baseline security metadata and regenerates the session ID.
         *
         * @return void
         */
        private static function initializeSession(): void {

            $now = time();

            self::setValue("initialized", true);
            self::setValue(self::CSRF_TOKEN_KEY, self::generateCsrfToken());
            self::setValue("createdAt", $now);
            self::setValue("lastActivityAt", $now);
            self::setValue("lastRegeneratedAt", $now);
            self::setValue("fingerprint", self::buildFingerprint());

            self::regenerate();

        }

        /**
         * Configures runtime session options before session_start().
         *
         * Sets strict mode, cookie-only transport, disabled URL SID, HttpOnly cookies,
         * SameSite protection, and the Secure cookie flag when HTTPS or server port 443 is detected.
         * Uses a session cookie scoped to the site root with no explicit domain.
         *
         * @return void
         */
        private static function configureSessionOptions(): void {

            $isSecure = (
                (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off") ||
                (($_SERVER["SERVER_PORT"] ?? null) == 443)
            );

            ini_set("session.use_strict_mode", "1");
            ini_set("session.use_only_cookies", "1");
            ini_set("session.use_trans_sid", "0");

            session_name((string)self::setting(self::ENV_SESSION_NAME));

            session_set_cookie_params(
                [
                    "lifetime" => 0,
                    "path"     => "/",
                    "secure"   => $isSecure,
                    "httponly" => true,
                    "samesite" => "Lax",
                ],
            );
        }

        /**
         * Ensures required security metadata exists for pre-existing sessions.
         *
         * Supports migration from the legacy "token" key to "csrfToken" and backfills timestamps
         * and the user-agent fingerprint when missing. A missing fingerprint also triggers ID regeneration.
         *
         * @return void
         */
        private static function ensureSessionSecurityMetadata(): void {

            $now = time();

            if (!self::isSet(self::CSRF_TOKEN_KEY)) {
                $legacyToken = self::getValue("token", null);
                if (is_string($legacyToken) && $legacyToken !== "") {
                    self::setValue(self::CSRF_TOKEN_KEY, $legacyToken);
                } else {
                    self::setValue(self::CSRF_TOKEN_KEY, self::generateCsrfToken());
                }
            }

            if (!self::isSet("createdAt")) {
                self::setValue("createdAt", $now);
            }

            if (!self::isSet("lastActivityAt")) {
                self::setValue("lastActivityAt", $now);
            }

            if (!self::isSet("lastRegeneratedAt")) {
                self::setValue("lastRegeneratedAt", $now);
            }

            if (!self::isSet("fingerprint")) {
                self::setValue("fingerprint", self::buildFingerprint());
                self::regenerate();
            }
        }

        /**
         * Generates a 256-bit CSRF token, encoded as 64 lowercase hexadecimal characters.
         * Uses an OpenSSL fallback if random_bytes() throws.
         *
         * @return string
         *
         * @throws RandomException If random_bytes() throws and the OpenSSL fallback is unavailable
         *                          or does not return exactly 32 bytes.
         */
        private static function generateCsrfToken(): string {

            try {
                return bin2hex(random_bytes(32));
            } catch (RandomException $exception) {
                if (function_exists("openssl_random_pseudo_bytes")) {
                    $bytes = openssl_random_pseudo_bytes(32);
                    if (strlen($bytes) === 32) {
                        return bin2hex($bytes);
                    }
                }

                throw $exception;
            }
        }

        /**
         * Checks whether the current session exceeded its absolute or inactivity timeout.
         * A missing or non-positive creation/activity timestamp is treated as expired.
         *
         * @return bool True when expired; otherwise false.
         */
        private static function isSessionExpired(): bool {

            $now = time();
            $createdAt = (int)self::getValue("createdAt", 0);
            $lastActivityAt = (int)self::getValue("lastActivityAt", 0);

            if ($createdAt <= 0 || $lastActivityAt <= 0) {
                return true;
            }

            if (($now - $createdAt) > self::setting(self::ENV_ABSOLUTE_TIMEOUT_SECONDS)) {
                return true;
            }

            return ($now - $lastActivityAt) > self::setting(self::ENV_INACTIVITY_TIMEOUT_SECONDS);
        }

        /**
         * Performs periodic rotation when the configured interval since the last rotation has elapsed.
         *
         * @return void
         */
        private static function rotateSessionIdIfNeeded(): void {

            $lastRegeneratedAt = (int)self::getValue("lastRegeneratedAt", 0);
            if ((time() - $lastRegeneratedAt) <= self::setting(self::ENV_ROTATION_INTERVAL_SECONDS)) {
                return;
            }

            self::rotate();

        }

        /**
         * Periodic rotation. Keeps the old session briefly (marked as superseded) so parallel
         * in-flight requests carrying the old ID can complete during the grace period, provided the
         * request passes the other validity checks. Do not use for privilege changes; use regenerate()
         * for those. If session_regenerate_id() fails, restores the prior session data and returns
         * without rotating.
         *
         * @return void
         */
        private static function rotate(): void {

            $oldSessionData = $_SESSION;
            $oldSessionId = session_id();
            $now = time();

            $_SESSION[self::SUPERSEDED_AT_KEY] = $now;
            $_SESSION[self::SUPERSEDED_BY_KEY] = "";

            if (!session_regenerate_id()) {
                $_SESSION = $oldSessionData;

                return;
            }

            $newSessionId = session_id();
            unset($_SESSION[self::SUPERSEDED_AT_KEY], $_SESSION[self::SUPERSEDED_BY_KEY]);
            $_SESSION[self::SUPERSEDED_FROM_KEY] = $oldSessionId;
            $_SESSION["lastRegeneratedAt"] = $now;

            session_write_close();

            session_id($oldSessionId);
            session_start();
            $_SESSION[self::SUPERSEDED_BY_KEY] = $newSessionId;
            session_write_close();

            session_id($newSessionId);
            session_start();

        }

        /**
         * Switches requests from a superseded session to its successor before mutations.
         * Returns false when the old session has no recorded successor; otherwise returns true.
         *
         * @return bool Whether mutation may proceed.
         */
        private static function useSuccessorSessionForMutations(): bool {

            $supersededAt = self::getValue(self::SUPERSEDED_AT_KEY, 0);
            $successorSessionId = self::getValue(self::SUPERSEDED_BY_KEY, null);
            if ((int)$supersededAt > 0 && (!is_string($successorSessionId) || $successorSessionId === "")) {
                return false;
            }

            if (!is_string($successorSessionId) || $successorSessionId === "" || session_id() === $successorSessionId) {
                return true;
            }

            session_write_close();
            session_id($successorSessionId);
            session_start();

            return true;
        }

        /**
         * Builds a fingerprint from the current request's user-agent string.
         *
         * The fingerprint is a SHA-256 hash, including when the user-agent header is absent.
         *
         * @return string
         */
        private static function buildFingerprint(): string {

            return hash("sha256", (string)($_SERVER["HTTP_USER_AGENT"] ?? ""));
        }

        /**
         * Validates active session integrity.
         *
         * A session is invalid when initialization is missing, expiry limits are exceeded, or the
         * request fingerprint does not match the stored fingerprint. These cases destroy the current
         * session and expire its cookie. Revoked sessions and grace-period-expired superseded sessions
         * are invalidated without expiring the cookie. A superseded session with no recorded successor
         * is reported invalid but is not destroyed here. Valid current sessions update activity metadata
         * and may rotate the session ID; a superseded session is temporarily accepted without extending
         * activity. Requires an active session; call start() first.
         *
         * @return bool True if the session is not valid, false otherwise.
         *
         * @see start()
         */
        public static function isNotValid(): bool {

            if (self::getValue(self::REVOKED_KEY, false) === true) {
                self::destroy(false);

                return true;
            }

            if (!isset($_SESSION["initialized"]) || !$_SESSION["initialized"]) {

                self::destroyCurrentSession(true);

                return true;

            }

            if (self::isSessionExpired()) {
                self::destroyCurrentSession(true);

                return true;
            }

            $expectedFingerprint = (string)self::getValue("fingerprint", "");
            if ($expectedFingerprint === "" || !hash_equals($expectedFingerprint, self::buildFingerprint())) {

                self::destroyCurrentSession(true);

                return true;

            }

            $supersededAt = (int)self::getValue(self::SUPERSEDED_AT_KEY, 0);
            if ($supersededAt > 0) {

                $successorSessionId = self::getValue(self::SUPERSEDED_BY_KEY, null);
                if (!is_string($successorSessionId) || $successorSessionId === "") {
                    return true;
                }

                if ((time() - $supersededAt) > self::setting(self::ENV_ROTATION_GRACE_SECONDS)) {
                    // The browser normally holds the new ID by now, so don't expire its cookie.
                    self::destroy(false);

                    return true;
                }

                // Within grace: allow the request, but don't rotate again or extend activity on the old session.
                return false;

            }

            self::setValue("lastActivityAt", time());
            self::rotateSessionIdIfNeeded();

            return false;

        }

        /**
         * Requests session-ID regeneration with deletion of the old session data, then updates its
         * last-regenerated timestamp. The regeneration result is not checked.
         *
         * Call after authentication or another privilege change, not for periodic rotation.
         *
         * @return void
         */
        public static function regenerate(): void {

            session_regenerate_id(true);
            self::setValue("lastRegeneratedAt", time());

        }

        /**
         * Retrieves the CSRF token from the active session. Call start() first so session metadata
         * has been initialized or backfilled.
         *
         * @return string The CSRF token.
         */
        public static function getCsrfToken(): string {

            return self::getValue(self::CSRF_TOKEN_KEY);

        }

        /**
         * Validates a provided CSRF token against the token stored in the active session using
         * hash_equals(). Call start() first so session metadata has been initialized or backfilled.
         *
         * @param string $token The CSRF token to validate.
         *
         * @return bool True if the token is valid, false otherwise.
         */
        public static function validateCsrfToken(string $token): bool {

            $sessionToken = self::getValue(self::CSRF_TOKEN_KEY, null);

            return is_string($sessionToken) && $sessionToken !== "" && hash_equals($sessionToken, $token);

        }

        /**
         * Checks whether there is a valid, logged-in session.
         *
         * Starts the session if required, applies full validity checks, and verifies that the logged-in
         * flag is explicitly true. Returns false for an invalid session or when the flag is not true.
         *
         * @return bool True when the session is valid and logged in; otherwise false.
         */
        public static function isValidLoggedInSession(): bool {

            self::start();
            if (self::isNotValid()) {
                return false;
            }

            return self::getValue("loggedIn", false) === true;

        }

        /**
         * Securely destroys the active session.
         *
         * Clears and destroys the active session. By default, also marks the adjacent session in a
         * rotation pair as revoked and expires the session cookie using the current cookie parameters.
         * Does nothing when no session is active.
         *
         * @param bool $expireCookie Whether to expire the session cookie and revoke its related session.
         *
         * @return void
         */
        public static function destroy(bool $expireCookie = true): void {

            if (session_status() !== PHP_SESSION_ACTIVE) {
                return;
            }

            if ($expireCookie) {
                self::revokeRelatedSession();
            }

            self::destroyCurrentSession($expireCookie);

        }

        /**
         * Marks the adjacent predecessor or successor session in a rotation pair as revoked, if present.
         *
         * @return void
         */
        private static function revokeRelatedSession(): void {

            $currentSessionId = session_id();
            $relatedSessionId = $_SESSION[self::SUPERSEDED_BY_KEY]
                ?? $_SESSION[self::SUPERSEDED_FROM_KEY]
                ?? null;

            $_SESSION[self::REVOKED_KEY] = true;
            session_write_close();

            if (is_string($relatedSessionId) && $relatedSessionId !== "" && $relatedSessionId !== $currentSessionId) {
                session_id($relatedSessionId);
                if (session_start()) {
                    if (session_id() === $relatedSessionId) {
                        $_SESSION[self::REVOKED_KEY] = true;
                    }
                    session_write_close();
                }
            }

            session_id($currentSessionId);
            session_start();

        }

        /**
         * Clears and destroys the active session and optionally expires its cookie.
         *
         * @param bool $expireCookie Whether to expire the session cookie.
         *
         * @return void
         */
        private static function destroyCurrentSession(bool $expireCookie): void {

            if (session_status() !== PHP_SESSION_ACTIVE) {
                return;
            }

            $_SESSION = [];

            if ($expireCookie) {
                $cookieParams = session_get_cookie_params();
                setcookie(session_name(), "", [
                    "expires"  => time() - 3600,
                    "path"     => $cookieParams["path"] ?? "/",
                    "domain"   => $cookieParams["domain"] ?? "",
                    "secure"   => (bool)($cookieParams["secure"] ?? false),
                    "httponly" => (bool)($cookieParams["httponly"] ?? true),
                    "samesite" => $cookieParams["samesite"] ?? "Lax",
                ]);
            }

            session_unset();
            session_destroy();

        }

        /**
         * Sets multiple session values from an array. If the current session is marked superseded and
         * has a recorded successor, the mutation is applied to that successor.
         *
         * @param array<array-key, mixed> $keyedValues Session keys and their values.
         *
         * @return void
         */
        public static function setValues(array $keyedValues): void {

            if (!self::useSuccessorSessionForMutations()) {
                return;
            }

            foreach ($keyedValues as $key => $value) {
                $_SESSION[$key] = $value;
            }

        }

        /**
         * Sets a single session value. If the current session is marked superseded and has a recorded
         * successor, the mutation is applied to that successor.
         *
         * @param string $key The key of the session value to set.
         * @param mixed $value The value to set for the session key.
         *
         * @return void
         */
        public static function setValue(string $key, mixed $value): void {

            if (!self::useSuccessorSessionForMutations()) {
                return;
            }

            $_SESSION[$key] = $value;

        }

        /**
         * Gets a value from the active session, optionally returning a default when the key is absent
         * or null.
         *
         * @param string $key The session key to return.
         * @param mixed $default The value to return when the key is absent or null. The "__UNDEFINED__" sentinel
         *                       means no default was provided; in that case, the session offset is
         *                       accessed directly and a missing key can raise an undefined-key warning.
         *
         * @return mixed The session value or, when provided, the default.
         */
        public static function getValue(string $key, mixed $default = "__UNDEFINED__"): mixed {

            if ($default !== "__UNDEFINED__") {
                return $_SESSION[$key] ?? $default;
            }

            return $_SESSION[$key];

        }

        /**
         * Checks whether a session key exists and is not null in the active session.
         *
         * @param string $key The key to check.
         *
         * @return bool True if the key is set, false otherwise.
         */
        public static function isSet(string $key): bool {

            return isset($_SESSION[$key]);

        }

    }