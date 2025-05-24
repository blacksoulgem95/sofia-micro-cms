<?php

/**
 * Middleware for authenticating JWT tokens in request headers.
 * Verifies token validity, checks if token is invalidated, and passes decoded user data to request attributes.
 *
 * @param \Psr\Http\Message\ServerRequestInterface $request The incoming request.
 * @param callable $handler The next request handler.
 * @return \Psr\Http\Message\ResponseInterface
 */
function authMiddleware($request, $handler)
{
    $auth = $request->getHeaderLine("Authorization");
    if (!$auth || !preg_match("/Bearer\\s+(.*)/", $auth, $matches)) {
        return (new \Slim\Psr7\Response())->withStatus(401);
    }
    try {
        $decoded = \Firebase\JWT\JWT::decode(
            $matches[1],
            new \Firebase\JWT\Key(JWT_SECRET, "HS256")
        );

        // Check if JWT token is invalidated (blacklisted)
        $stmt = db()->prepare("SELECT 1 FROM invalidated_jwts WHERE jwt_token = ?");
        $stmt->execute([$matches[1]]);
        if ($stmt->fetch()) {
            // Token is invalidated, reject request
            return (new \Slim\Psr7\Response())->withStatus(401);
        }

        $request = $request->withAttribute("user", $decoded);
        return $handler->handle($request);
    } catch (Exception $e) {
        return (new \Slim\Psr7\Response())->withStatus(401);
    }
}

/**
 * Handles user registration if registration is enabled via environment variable.
 *
 * Checks the environment variable REGISTRATION_ENABLED to determine if
 * new user registrations are allowed. If disabled, returns 403 Forbidden.
 *
 * Expects a POST request with JSON body containing 'username' and 'password'.
 *
 * Hashes the password using bcrypt and stores the new user in the database.
 * If the username is taken or input is invalid, returns appropriate error.
 *
 * @param \Psr\Http\Message\ServerRequestInterface $request The incoming HTTP request.
 * @param \Psr\Http\Message\ResponseInterface $response The outgoing HTTP response.
 * @return \Psr\Http\Message\ResponseInterface JSON response indicating success or error.
 */
function register($request, $response)
{
    // Check if registration is enabled via env variable
    if (getenv('REGISTRATION_ENABLED') !== 'true') {
        return $response->withStatus(403)->withHeader('Content-Type', 'application/json')
            ->write(json_encode(['error' => 'Registration is disabled']));
    }

    $data = (array) $request->getParsedBody();

    if (!isset($data['username']) || !isset($data['password']) || !isset($data['password_confirm'])) {
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json')
            ->write(json_encode(['error' => 'Username, password and password confirmation are required']));
    }

    $username = trim($data['username']);
    $password = $data['password'];
    $passwordConfirm = $data['password_confirm'];

    if ($username === '' || $password === '' || $passwordConfirm === '') {
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json')
            ->write(json_encode(['error' => 'Username, password and password confirmation cannot be empty']));
    }

    if ($password !== $passwordConfirm) {
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json')
            ->write(json_encode(['error' => 'Password and password confirmation do not match']));
    }

    // Check if username already exists
    $stmt = db()->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->execute([$username]);
    if ($stmt->fetch()) {
        return $response->withStatus(409)->withHeader('Content-Type', 'application/json')
            ->write(json_encode(['error' => 'Username already taken']));
    }

    // Hash password using bcrypt
    $passwordHash = password_hash($password, PASSWORD_BCRYPT);

    // Insert new user
    $stmt = db()->prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)");
    if (!$stmt->execute([$username, $passwordHash])) {
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json')
            ->write(json_encode(['error' => 'Failed to register user']));
    }

    // Respond with success
    return $response->withStatus(201)->withHeader('Content-Type', 'application/json')
        ->write(json_encode(['message' => 'User registered successfully']));
}

/**
 * Handles user logout.
 *
 * Invalidate the user's token by storing it in a blacklist database table.
 *
 * @param \Psr\Http\Message\ServerRequestInterface $request Incoming HTTP request.
 * @param \Psr\Http\Message\ResponseInterface $response Outgoing HTTP response.
 * @return \Psr\Http\Message\ResponseInterface Response indicating successful logout.
 */
function logout($request, $response)
{
    $auth = $request->getHeaderLine("Authorization");
    if (!$auth || !preg_match("/Bearer\s+(.*)/", $auth, $matches)) {
        // No token provided, just return success anyway
        return $response->withStatus(204);
    }
    $jwtToken = $matches[1];

    // Decode token to get expiration time
    try {
        $decoded = \Firebase\JWT\JWT::decode(
            $jwtToken,
            new \Firebase\JWT\Key(JWT_SECRET, "HS256")
        );
    } catch (Exception $e) {
        // Token invalid or expired, simply return 204
        return $response->withStatus(204);
    }

    $expiry = isset($decoded->exp) ? (int)$decoded->exp : time();

    // Add token to invalidated_jwts table as the primary key with expires_at column
    $stmt = db()->prepare("INSERT INTO invalidated_jwts (jwt_token, expires_at) VALUES (?, ?) ON DUPLICATE KEY UPDATE expires_at = VALUES(expires_at)");
    $stmt->execute([$jwtToken, date('Y-m-d H:i:s', $expiry)]);

    return $response->withStatus(204);
}

/**
 * Cleans up expired invalidated JWT tokens from the database.
 *
 * This function can be called via a cron job or scheduled task
 * to remove invalidated JWT entries that have passed their expiration
 * date to keep the database clean.
 */
function cleanupExpiredInvalidatedTokens()
{
    $stmt = db()->prepare("DELETE FROM invalidated_jwts WHERE expires_at < NOW()");
    $stmt->execute();
}

/**
 * Handles /auth/register-2fa POST route.
 *
 * This function accepts a POST request containing a user ID in the request body.
 * It calls the `register2FA` function to generate a new Base32 secret key for the user,
 * stores it in the database, and enables 2FA for that user.
 * The generated secret is then returned in the JSON response for the user to use
 * when setting up their 2FA application.
 *
 * If the user ID is missing from the request, it responds with a 400 status and error message.
 *
 * @param \Psr\Http\Message\ServerRequestInterface $request Incoming HTTP request
 * @param \Psr\Http\Message\ResponseInterface $response HTTP response that will be returned
 * @return \Psr\Http\Message\ResponseInterface JSON response with the generated 2FA secret or error
 */
function handleRegister2FA($request, $response) {
    $data = (array) $request->getParsedBody();
    if (!isset($data['user_id'])) {
        return $response->withStatus(400)->write(json_encode(['error' => 'User ID required']));
    }
    $secret = register2FA($data['user_id']);
    $response->getBody()->write(json_encode(['secret' => $secret]));
    return $response->withHeader('Content-Type', 'application/json');
}

/**
 * Handles /auth/send-2fa-code POST route.
 *
 * This function accepts a POST request containing a user ID.
 * It retrieves the user's email and 2FA secret from the database.
 * If the user or secret is not found, it returns a 400 error response.
 * Otherwise, it generates the current TOTP code using the stored secret,
 * sends this code via email to the user's email address using `sendTOTPEmail`.
 * It returns a JSON response indicating success or failure of sending the email.
 *
 * Used for out-of-band communication of the 2FA code if needed.
 *
 * @param \Psr\Http\Message\ServerRequestInterface $request Incoming HTTP request
 * @param \Psr\Http\Message\ResponseInterface $response HTTP response that will be returned
 * @return \Psr\Http\Message\ResponseInterface JSON response indicating success or error
 */
function handleSend2FACode($request, $response) {
    $data = (array) $request->getParsedBody();
    if (!isset($data['user_id'])) {
        return $response->withStatus(400)->write(json_encode(['error' => 'User ID required']));
    }
    $stmt = db()->prepare("SELECT email, two_fa_secret FROM users WHERE id = ?");
    $stmt->execute([$data['user_id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user || empty($user['two_fa_secret'])) {
        return $response->withStatus(400)->write(json_encode(['error' => 'User or 2FA secret not found']));
    }
    $sent = sendTOTPEmail($user['email'], $user['two_fa_secret']);
    if (!$sent) {
        return $response->withStatus(500)->write(json_encode(['error' => 'Failed to send email']));
    }
    $response->getBody()->write(json_encode(['success' => true]));
    return $response->withHeader('Content-Type', 'application/json');
}

/**
  * Verifies a TOTP 2FA code against the stored secret.
  * Checks code in a time window of current, previous, and next 30 seconds.
  *
  * @param string $secret Base32 encoded 2FA secret.
  * @param string $code User-provided 6-digit code.
  * @return bool True if code is valid, false otherwise.
  */
function verify2FACode($secret, $code)
{
    if (!$secret || !$code) {
        return false;
    }
    $secret = str_replace(" ", "", $secret);
    $currentTimeSlice = floor(time() / 30);

    for ($i = -1; $i <= 1; ++$i) {
        $calculatedCode = calculateOTP($secret, $currentTimeSlice + $i);
        if ($calculatedCode === $code) {
            return true;
        }
    }
    return false;
}

/**
 * Handles /auth/verify-2fa POST route.
 *
 * This function is called after the initial login to verify the submitted 2FA code.
 * It expects a user ID and the 2FA code in the POST body.
 * The function fetches the user's 2FA secret from the database and verifies the code.
 * It returns a JSON response indicating success or failure.
 *
 * If input is missing or invalid, a 400 response is returned.
 * If the 2FA code is invalid, a 401 unauthorized response is returned.
 *
 * @param \Psr\Http\Message\ServerRequestInterface $request Incoming HTTP request
 * @param \Psr\Http\Message\ResponseInterface $response HTTP response to return
 * @return \Psr\Http\Message\ResponseInterface JSON response indicating success or error
 */
function handleVerify2FA($request, $response)
{
    $data = (array) $request->getParsedBody();
    if (!isset($data['user_id']) || !isset($data['two_fa_code'])) {
        return $response->withStatus(400)->write(json_encode(['error' => 'Missing user_id or two_fa_code']));
    }
    $stmt = db()->prepare("SELECT two_fa_secret FROM users WHERE id = ?");
    $stmt->execute([$data['user_id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user || empty($user['two_fa_secret'])) {
        return $response->withStatus(400)->write(json_encode(['error' => 'User or 2FA secret not found']));
    }
    if (!verify2FACode($user['two_fa_secret'], $data['two_fa_code'])) {
        $body = (new \Slim\Psr7\Stream(fopen('php://temp', 'r+')));
        $body->write(json_encode(['error' => 'Invalid 2FA code']));
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json')->withBody($body);
    }
    $response->getBody()->write(json_encode(['success' => true]));
    return $response->withHeader('Content-Type', 'application/json');
}
 * @param string $secret Base32 encoded 2FA secret.
 * @param string $code User-provided 6-digit code.
 * @return bool True if code is valid, false otherwise.
 */
function verify2FACode($secret, $code)
{
    if (!$secret || !$code) {
        return false;
    }
    $secret = str_replace(" ", "", $secret);
    $currentTimeSlice = floor(time() / 30);

    for ($i = -1; $i <= 1; ++$i) {
        $calculatedCode = calculateOTP($secret, $currentTimeSlice + $i);
        if ($calculatedCode === $code) {
            return true;
        }
    }
    return false;
}

/**
 * Calculates the 6-digit TOTP code for a given secret and time slice.
 *
 * @param string $secret Base32 encoded secret.
 * @param int $timeSlice Time slice value (usually floor(time()/30)).
 * @return string The 6-digit OTP, zero-padded.
 */
function calculateOTP($secret, $timeSlice)
{
    $key = base32Decode($secret);
    $time = pack("N*", 0) . pack("N*", $timeSlice);
    $hash = hash_hmac("sha1", $time, $key, true);
    $offset = ord(substr($hash, -1)) & 0x0f;
    $otp =
        ((ord($hash[$offset + 0]) & 0x7f) << 24) |
        ((ord($hash[$offset + 1]) & 0xff) << 16) |
        ((ord($hash[$offset + 2]) & 0xff) << 8) |
        (ord($hash[$offset + 3]) & 0xff);
    $otp = $otp % 1000000;
    return str_pad($otp, 6, "0", STR_PAD_LEFT);
}

/**
 * Decodes a Base32 encoded string into raw binary.
 *
 * @param string $secret Base32 string.
 * @return string Decoded binary string or empty string on invalid input.
 */
function base32Decode($secret)
{
    if (empty($secret)) {
        return "";
    }

    $base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    $base32charsFlipped = array_flip(str_split($base32chars));

    $paddingCharCount = substr_count($secret, "=");
    $allowedValues = [6, 4, 3, 1, 0];
    if (!in_array($paddingCharCount, $allowedValues)) {
        return false;
    }

    $secret = str_replace("=", "", $secret);
    $secret = strtoupper($secret);
    $binaryString = "";

    foreach (str_split($secret) as $char) {
        if (!isset($base32charsFlipped[$char])) {
            return false;
        }
        $binaryString .= str_pad(
            decbin($base32charsFlipped[$char]),
            5,
            "0",
            STR_PAD_LEFT
        );
    }

    $eightBits = str_split($binaryString, 8);
    $decoded = "";
    foreach ($eightBits as $bits) {
        $decoded .= chr(bindec($bits));
    }
    return $decoded;
}

/**
 * Sends a current TOTP 2FA code to a user's email.
 *
 * @param string $to_email Recipient email.
 * @param string $secret User's 2FA secret to generate current code.
 * @return bool True if mail sent successfully, false otherwise.
 */
function sendTOTPEmail($to_email, $secret)
{
    $code = calculateOTP($secret, floor(time() / 30));
    $subject = "Your Two-Factor Authentication Code";
    $message = "Your authentication code is: " . $code . "\nThis code is valid for 30 seconds.";
    $headers = "From: no-reply@example.com\r\n" .
        "Content-Type: text/plain; charset=UTF-8\r\n";

    return mail($to_email, $subject, $message, $headers);
}

/**
 * Processes login with username and password.
 * Validates credentials against DB and checks 2FA if enabled.
 * Returns a JWT token on successful authentication.
 *
 * @param \Psr\Http\Message\ServerRequestInterface $request HTTP request.
 * @param \Psr\Http\Message\ResponseInterface $response HTTP response.
 * @return \Psr\Http\Message\ResponseInterface JSON response with token or error.
 */
function login($request, $response)
{
    $data = (array) $request->getParsedBody();

    if (!isset($data["username"]) || !isset($data["password"])) {
        return $response->withStatus(400);
    }

    $stmt = db()->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$data["username"]]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Check if the user was found and verify the provided password
    // against the stored password hash using password_verify.
    // password_verify securely compares the plain text password with
    // the hashed password stored in the database.
    // If the user does not exist or password is incorrect, return 401 Unauthorized.
    // Use bcrypt specifically to verify the password hash
    if (
        !$user || 
        !password_verify($data["password"], $user["password_hash"]) || 
        !preg_match('/^\$2y\$/', $user["password_hash"]) // Ensure the hash used is bcrypt ($2y$ prefix)
    ) {
        return $response->withStatus(401);
    }

    if ($user["is_two_fa_enabled"]) {
        if (!isset($data["two_fa_code"]) || !verify2FACode($user["two_fa_secret"], $data["two_fa_code"])) {
            $body = (new \Slim\Psr7\Stream(fopen("php://temp", "r+")));
            $body->write(json_encode(["error" => "2FA code required or invalid"]));
            return $response->withStatus(401)->withHeader("Content-Type", "application/json")->withBody($body);
        }
    }
    $payload = [
        "user_id" => $user["id"],
        "username" => $user["username"],
        "iat" => time(),
        "exp" => time() + 3600
    ];

    $jwt = \Firebase\JWT\JWT::encode($payload, JWT_SECRET, "HS256");
    $response->getBody()->write(json_encode(["token" => $jwt]));
    return $response->withHeader("Content-Type", "application/json");
}

/**
 * Registers 2FA for a user by generating and storing a new Base32 secret,
 * enabling 2FA, and returning the secret for user setup.
 *
 * @param int $userId User ID.
 * @return string The Base32 secret string.
 */
function register2FA($userId)
{
    $base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ($i = 0; $i < 16; $i++) {
        $secret .= $base32chars[random_int(0, 31)];
    }

    $stmt = db()->prepare("UPDATE users SET two_fa_secret = ?, is_two_fa_enabled = TRUE, modified_at = NOW() WHERE id = ?");
    $stmt->execute([$secret, $userId]);

    return $secret;
}