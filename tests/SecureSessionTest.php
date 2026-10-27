<?php

    declare(strict_types=1);

    namespace GrangeFencing\SecureSession\Tests;

    use GrangeFencing\SecureSession\SecureSession;
    use PHPUnit\Framework\TestCase;

    final class SecureSessionTest extends TestCase {

        private string $sessionSavePath;
        private string $originalSavePath;
        private string $originalSessionName;
        private array $originalCookieParams;
        private array $originalSessionIni = [];
        private array $originalEnvironment = [];
        private mixed $originalUserAgent;

        private const array ENV_SETTINGS = [
            "SECURE_SESSION_NAME",
            "SECURE_SESSION_INACTIVITY_TIMEOUT_SECONDS",
            "SECURE_SESSION_ABSOLUTE_TIMEOUT_SECONDS",
            "SECURE_SESSION_ROTATION_INTERVAL_SECONDS",
            "SECURE_SESSION_ROTATION_GRACE_SECONDS",
        ];

        private const array SESSION_INI_SETTINGS = [
            "session.use_strict_mode",
            "session.use_only_cookies",
            "session.use_trans_sid",
        ];

        protected function setUp(): void {

            parent::setUp();

            if(session_status() === PHP_SESSION_ACTIVE) {
                session_destroy();
            }

            $this->originalSavePath = session_save_path();
            $this->originalSessionName = session_name();
            $this->originalCookieParams = session_get_cookie_params();
            foreach(self::SESSION_INI_SETTINGS as $setting) {
                $this->originalSessionIni[$setting] = ini_get($setting);
            }

            foreach(self::ENV_SETTINGS as $setting) {
                $this->originalEnvironment[$setting] = $_ENV[$setting] ?? null;
                unset($_ENV[$setting]);
            }

            $this->originalUserAgent = $_SERVER["HTTP_USER_AGENT"] ?? null;
            $_SERVER["HTTP_USER_AGENT"] = "SecureSessionTest/1.0";

            $this->sessionSavePath = sys_get_temp_dir() . "/secure-session-test-" . bin2hex(random_bytes(8));
            mkdir($this->sessionSavePath, 0700);
            session_save_path($this->sessionSavePath);
        }

        protected function tearDown(): void {

            if(session_status() === PHP_SESSION_ACTIVE) {
                session_destroy();
            }

            $_SESSION = [];

            foreach(self::ENV_SETTINGS as $setting) {
                if($this->originalEnvironment[$setting] === null) {
                    unset($_ENV[$setting]);
                } else {
                    $_ENV[$setting] = $this->originalEnvironment[$setting];
                }
            }

            if($this->originalUserAgent === null) {
                unset($_SERVER["HTTP_USER_AGENT"]);
            } else {
                $_SERVER["HTTP_USER_AGENT"] = $this->originalUserAgent;
            }

            session_save_path($this->originalSavePath);
            session_name($this->originalSessionName);
            session_set_cookie_params($this->originalCookieParams);
            foreach($this->originalSessionIni as $setting => $value) {
                ini_set($setting, (string)$value);
            }

            foreach(array_diff(scandir($this->sessionSavePath), [".", ".."]) as $file) {
                unlink($this->sessionSavePath . "/" . $file);
            }
            rmdir($this->sessionSavePath);

            parent::tearDown();
        }

        public function testStartInitializesSessionAndConfiguresSecureCookies(): void {

            SecureSession::start();

            self::assertSame(PHP_SESSION_ACTIVE, session_status());
            self::assertTrue(SecureSession::isSet("initialized"));
            self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', SecureSession::getCsrfToken());
            self::assertSame(64, strlen(SecureSession::getCsrfToken()));
            self::assertSame("SecureSessionTest/1.0", $_SERVER["HTTP_USER_AGENT"]);
            self::assertSame(hash("sha256", $_SERVER["HTTP_USER_AGENT"]), SecureSession::getValue("fingerprint"));

            $cookieParams = session_get_cookie_params();
            self::assertSame("/", $cookieParams["path"]);
            self::assertTrue($cookieParams["httponly"]);
            self::assertSame("Lax", $cookieParams["samesite"]);
            self::assertSame("1", ini_get("session.use_strict_mode"));
            self::assertSame("1", ini_get("session.use_only_cookies"));
            self::assertSame("0", ini_get("session.use_trans_sid"));
        }

        public function testCsrfTokenValidationAcceptsOnlyTheSessionToken(): void {

            SecureSession::start();
            $token = SecureSession::getCsrfToken();

            self::assertTrue(SecureSession::validateCsrfToken($token));
            self::assertFalse(SecureSession::validateCsrfToken(str_repeat("0", 64)));
            self::assertFalse(SecureSession::validateCsrfToken(""));
        }

        public function testInvalidFingerprintInvalidatesAndDestroysSession(): void {

            SecureSession::start();
            $_SERVER["HTTP_USER_AGENT"] = "DifferentAgent/1.0";

            self::assertTrue(SecureSession::isNotValid());
            self::assertSame(PHP_SESSION_NONE, session_status());
        }

        public function testInactivityTimeoutInvalidatesSession(): void {

            $_ENV["SECURE_SESSION_INACTIVITY_TIMEOUT_SECONDS"] = "1";
            SecureSession::start();
            SecureSession::setValue("lastActivityAt", time() - 2);

            self::assertTrue(SecureSession::isNotValid());
            self::assertSame(PHP_SESSION_NONE, session_status());
        }

        public function testAbsoluteTimeoutInvalidatesSession(): void {

            $_ENV["SECURE_SESSION_ABSOLUTE_TIMEOUT_SECONDS"] = "1";
            SecureSession::start();
            SecureSession::setValue("createdAt", time() - 2);

            self::assertTrue(SecureSession::isNotValid());
            self::assertSame(PHP_SESSION_NONE, session_status());
        }

        public function testPeriodicRotationPreservesGraceRequestsAndRoutesMutationToSuccessor(): void {

            SecureSession::start();
            SecureSession::setValue("lastRegeneratedAt", time() - 301);
            $oldSessionId = session_id();

            self::assertFalse(SecureSession::isNotValid());
            $newSessionId = session_id();
            self::assertNotSame($oldSessionId, $newSessionId);

            session_write_close();
            session_id($oldSessionId);
            self::assertTrue(session_start());

            self::assertFalse(SecureSession::isNotValid());
            SecureSession::setValue("writtenDuringGrace", "successor");

            self::assertSame($newSessionId, session_id());
            self::assertSame("successor", SecureSession::getValue("writtenDuringGrace"));
        }

        public function testLoggedInCheckStartsSessionAndRequiresExplicitTrue(): void {

            self::assertFalse(SecureSession::isValidLoggedInSession());
            SecureSession::setValue("loggedIn", true);

            self::assertTrue(SecureSession::isValidLoggedInSession());
        }

        public function testDestroyEndsSession(): void {

            SecureSession::start();
            SecureSession::destroy();

            self::assertSame(PHP_SESSION_NONE, session_status());
        }

    }
