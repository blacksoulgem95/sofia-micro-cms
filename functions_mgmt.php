<?php

/**
 * Paginates a database query.
 *
 * @param string $query The SQL query string, not including LIMIT/OFFSET.
 * @param array $params Query parameters for prepared statements.
 * @param int $page Page number (1-based).
 * @param int $limit Number of items per page.
 * @return array Result rows.
 */
function paginateMgmt($query, $params, $page, $limit = 10)
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
function getPostsMgmt($request, $response)
{
    $page = $request->getQueryParams()["page"] ?? 1;
    $data = paginateMgmt(
        "SELECT posts.*, categories.name AS category FROM posts LEFT JOIN categories ON posts.category_id = categories.id ORDER BY posts.created_at DESC",
        [],
        $page
    );
    $response->getBody()->write(json_encode($data));
    return $response->withHeader("Content-Type", "application/json");
}

function createPostMgmt($request, $response)
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

// Categories
function getCategoriesMgmt($request, $response)
{
    $stmt = db()->query("SELECT * FROM categories ORDER BY name");
    $response->getBody()->write(json_encode($stmt->fetchAll(PDO::FETCH_ASSOC)));
    return $response->withHeader("Content-Type", "application/json");
}

function createCategoryMgmt($request, $response)
{
    $data = (array) $request->getParsedBody();
    $stmt = db()->prepare("INSERT INTO categories (name) VALUES (?)");
    $stmt->execute([$data["name"]]);
    return $response->withStatus(201);
}

// Testimonials
function getTestimonialsMgmt($request, $response)
{
    $page = $request->getQueryParams()["page"] ?? 1;
    $data = paginateMgmt(
        "SELECT * FROM testimonials ORDER BY created_at DESC",
        [],
        $page
    );
    $response->getBody()->write(json_encode($data));
    return $response->withHeader("Content-Type", "application/json");
}

function createTestimonialMgmt($request, $response)
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
function getPortfolioMgmt($request, $response)
{
    $page = $request->getQueryParams()["page"] ?? 1;
    $data = paginateMgmt(
        "SELECT p.*, c.name as client FROM portfolio p LEFT JOIN clients c ON p.client_id = c.id ORDER BY p.created_at DESC",
        [],
        $page
    );
    $response->getBody()->write(json_encode($data));
    return $response->withHeader("Content-Type", "application/json");
}

function createPortfolioMgmt($request, $response)
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
function getClientsMgmt($request, $response)
{
    $stmt = db()->query("SELECT * FROM clients ORDER BY name");
    $response->getBody()->write(json_encode($stmt->fetchAll(PDO::FETCH_ASSOC)));
    return $response->withHeader("Content-Type", "application/json");
}

function createClientMgmt($request, $response)
{
    $data = (array) $request->getParsedBody();
    $stmt = db()->prepare("INSERT INTO clients (name) VALUES (?)");
    $stmt->execute([$data["name"]]);
    return $response->withStatus(201);
}

// Images
function uploadImageMgmt($request, $response)
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

function getImagesMgmt($request, $response)
{
    $stmt = db()->query("SELECT * FROM images ORDER BY uploaded_at DESC");
    $response->getBody()->write(json_encode($stmt->fetchAll(PDO::FETCH_ASSOC)));
    return $response->withHeader("Content-Type", "application/json");
}