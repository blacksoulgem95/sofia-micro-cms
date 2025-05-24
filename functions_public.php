<?php

/**
 * Fetches all published blog posts with pagination for public viewing.
 *
 * @param \Psr\Http\Message\ServerRequestInterface $request
 * @param \Psr\Http\Message\ResponseInterface $response
 * @return \Psr\Http\Message\ResponseInterface
 */
function getPosts($request, $response)
{
    $page = $request->getQueryParams()["page"] ?? 1;
    $stmt = db()->prepare(
        "SELECT posts.id, posts.title, posts.content, posts.created_at, categories.name AS category
         FROM posts
         LEFT JOIN categories ON posts.category_id = categories.id
         ORDER BY posts.created_at DESC
         LIMIT :limit OFFSET :offset"
    );

    $limit = 10;
    $offset = ($page - 1) * $limit;

    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);

    $stmt->execute();

    $posts = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $response->getBody()->write(json_encode($posts));
    return $response->withHeader("Content-Type", "application/json");
}

/**
 * Fetches public categories list.
 *
 * @param \Psr\Http\Message\ServerRequestInterface $request
 * @param \Psr\Http\Message\ResponseInterface $response
 * @return \Psr\Http\Message\ResponseInterface
 */
function getCategories($request, $response)
{
    $stmt = db()->query("SELECT id, name FROM categories ORDER BY name");
    $categories = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $response->getBody()->write(json_encode($categories));
    return $response->withHeader("Content-Type", "application/json");
}

/**
 * Fetches public testimonials for display.
 *
 * @param \Psr\Http\Message\ServerRequestInterface $request
 * @param \Psr\Http\Message\ResponseInterface $response
 * @return \Psr\Http\Message\ResponseInterface
 */
function getTestimonials($request, $response)
{
    $stmt = db()->query("SELECT author, content, company, role FROM testimonials ORDER BY created_at DESC");
    $testimonials = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $response->getBody()->write(json_encode($testimonials));
    return $response->withHeader("Content-Type", "application/json");
}

/**
 * Fetches portfolio items for public display.
 *
 * @param \Psr\Http\Message\ServerRequestInterface $request
 * @param \Psr\Http\Message\ResponseInterface $response
 * @return \Psr\Http\Message\ResponseInterface
 */
function getPortfolio($request, $response)
{
    $stmt = db()->query(
        "SELECT p.id, p.title, p.description, p.url, c.name AS client 
         FROM portfolio p 
         LEFT JOIN clients c ON p.client_id = c.id
         ORDER BY p.created_at DESC"
    );
    $portfolio = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $response->getBody()->write(json_encode($portfolio));
    return $response->withHeader("Content-Type", "application/json");
}

/**
 * Fetches clients list for public display.
 *
 * @param \Psr\Http\Message\ServerRequestInterface $request
 * @param \Psr\Http\Message\ResponseInterface $response
 * @return \Psr\Http\Message\ResponseInterface
 */
function getClients($request, $response)
{
    $stmt = db()->query("SELECT id, name, url FROM clients ORDER BY name");
    $clients = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $response->getBody()->write(json_encode($clients));
    return $response->withHeader("Content-Type", "application/json");
}

/**
 * Fetches images for public display.
 *
 * @param \Psr\Http\Message\ServerRequestInterface $request
 * @param \Psr\Http\Message\ResponseInterface $response
 * @return \Psr\Http\Message\ResponseInterface
 */
function getImages($request, $response)
{
    $stmt = db()->query("SELECT id, filename FROM images ORDER BY uploaded_at DESC");
    $images = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $response->getBody()->write(json_encode($images));
    return $response->withHeader("Content-Type", "application/json");
}