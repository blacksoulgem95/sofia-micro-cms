<?php

function db()
{
    static $pdo;
    if (!$pdo) {
        $dsn =
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4";
        $pdo = new PDO($dsn, DB_USER, DB_PASS);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }
    return $pdo;
}

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
        $request = $request->withAttribute("user", $decoded);
        return $handler->handle($request);
    } catch (Exception $e) {
        return (new \Slim\Psr7\Response())->withStatus(401);
    }
}

function login($request, $response)
{
    $data = (array) $request->getParsedBody();
    if ($data["username"] === "admin" && $data["password"] === "password") {
        $payload = ["user" => "admin", "iat" => time(), "exp" => time() + 3600];
        $jwt = \Firebase\JWT\JWT::encode($payload, JWT_SECRET, "HS256");
        $response->getBody()->write(json_encode(["token" => $jwt]));
        return $response->withHeader("Content-Type", "application/json");
    }
    return $response->withStatus(401);
}

function paginate($query, $params, $page, $limit = 10)
{
    $offset = ($page - 1) * $limit;
    $stmt = db()->prepare($query . " LIMIT :limit OFFSET :offset");
    foreach ($params as $key => $val) {
        $stmt->bindValue($key, $val);
    }
    $stmt->bindValue(":limit", $limit, PDO::PARAM_INT);
    $stmt->bindValue(":offset", $offset, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Posts
function getPosts($request, $response)
{
    $page = $request->getQueryParams()["page"] ?? 1;
    $data = paginate(
        "SELECT posts.*, categories.name AS category FROM posts LEFT JOIN categories ON posts.category_id = categories.id ORDER BY posts.created_at DESC",
        [],
        $page
    );
    $response->getBody()->write(json_encode($data));
    return $response->withHeader("Content-Type", "application/json");
}

function createPost($request, $response)
{
    $data = (array) $request->getParsedBody();
    $stmt = db()->prepare(
        "INSERT INTO posts (title, content, category_id, created_at) VALUES (?, ?, ?, NOW())"
    );
    $stmt->execute([
        $data["title"],
        $data["content"],
        $data["category_id"] ?? null,
    ]);
    return $response->withStatus(201);
}

// Categorie
function getCategories($request, $response)
{
    $stmt = db()->query("SELECT * FROM categories ORDER BY name");
    $response->getBody()->write(json_encode($stmt->fetchAll(PDO::FETCH_ASSOC)));
    return $response->withHeader("Content-Type", "application/json");
}

function createCategory($request, $response)
{
    $data = (array) $request->getParsedBody();
    $stmt = db()->prepare("INSERT INTO categories (name) VALUES (?)");
    $stmt->execute([$data["name"]]);
    return $response->withStatus(201);
}

// Testimonials
function getTestimonials($request, $response)
{
    $page = $request->getQueryParams()["page"] ?? 1;
    $data = paginate(
        "SELECT * FROM testimonials ORDER BY created_at DESC",
        [],
        $page
    );
    $response->getBody()->write(json_encode($data));
    return $response->withHeader("Content-Type", "application/json");
}

function createTestimonial($request, $response)
{
    $data = (array) $request->getParsedBody();
    $stmt = db()->prepare(
        "INSERT INTO testimonials (author, content, company, role, created_at) VALUES (?, ?, ?, ?, NOW())"
    );
    $stmt->execute([
        $data["author"],
        $data["content"],
        $data["company"],
        $data["role"],
    ]);
    return $response->withStatus(201);
}

// Portfolio
function getPortfolio($request, $response)
{
    $page = $request->getQueryParams()["page"] ?? 1;
    $data = paginate(
        "SELECT p.*, c.name as client FROM portfolio p LEFT JOIN clients c ON p.client_id = c.id ORDER BY p.created_at DESC",
        [],
        $page
    );
    $response->getBody()->write(json_encode($data));
    return $response->withHeader("Content-Type", "application/json");
}

function createPortfolio($request, $response)
{
    $data = (array) $request->getParsedBody();
    $stmt = db()->prepare(
        "INSERT INTO portfolio (title, description, url, client_id, created_at) VALUES (?, ?, ?, ?, NOW())"
    );
    $stmt->execute([
        $data["title"],
        $data["description"],
        $data["url"],
        $data["client_id"] ?? null,
    ]);
    return $response->withStatus(201);
}

// Clients
function getClients($request, $response)
{
    $stmt = db()->query("SELECT * FROM clients ORDER BY name");
    $response->getBody()->write(json_encode($stmt->fetchAll(PDO::FETCH_ASSOC)));
    return $response->withHeader("Content-Type", "application/json");
}

function createClient($request, $response)
{
    $data = (array) $request->getParsedBody();
    $stmt = db()->prepare("INSERT INTO clients (name) VALUES (?)");
    $stmt->execute([$data["name"]]);
    return $response->withStatus(201);
}

// Images
function uploadImage($request, $response)
{
    $uploadedFiles = $request->getUploadedFiles();
    if (!isset($uploadedFiles["image"])) {
        return $response->withStatus(400);
    }

    $image = $uploadedFiles["image"];
    if ($image->getError() === UPLOAD_ERR_OK) {
        $filename =
            uniqid() .
            "-" .
            preg_replace("/[^a-zA-Z0-9.\-_]/", "", $image->getClientFilename());
        $path = __DIR__ . "/uploads/" . $filename;
        $image->moveTo($path);

        $stmt = db()->prepare("INSERT INTO images (filename) VALUES (?)");
        $stmt->execute([$filename]);

        $response->getBody()->write(json_encode(["filename" => $filename]));
        return $response->withHeader("Content-Type", "application/json");
    }

    return $response->withStatus(500);
}

function getImages($request, $response)
{
    $stmt = db()->query("SELECT * FROM images ORDER BY uploaded_at DESC");
    $response->getBody()->write(json_encode($stmt->fetchAll(PDO::FETCH_ASSOC)));
    return $response->withHeader("Content-Type", "application/json");
}
