<?php
// index.php - Entry point
require "vendor/autoload.php";
require "config.php";
require "functions.php";

use Slim\Factory\AppFactory;
use Slim\Middleware\ErrorMiddleware;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$app = AppFactory::create();
$app->addRoutingMiddleware();
$app->add(
    new ErrorMiddleware(
        $app->getCallableResolver(),
        $app->getResponseFactory(),
        true,
        true,
        true
    )
);

// Middleware per limitare richieste allo stesso host
$app->add(function (Request $request, $handler) {
    $origin = $request->getHeaderLine("Origin");
    if ($origin && parse_url($origin, PHP_URL_HOST) !== $_SERVER["HTTP_HOST"]) {
        $response = new \Slim\Psr7\Response();
        return $response->withStatus(403);
    }
    return $handler->handle($request);
});

// Login route
$app->post("/login", "login");

// Rotte protette da autenticazione
$app->group("", function ($group) {
    // Posts
    $group->get("/posts", "getPosts");
    $group->post("/posts", "createPost");

    // Categories
    $group->get("/categories", "getCategories");
    $group->post("/categories", "createCategory");

    // Testimonials
    $group->get("/testimonials", "getTestimonials");
    $group->post("/testimonials", "createTestimonial");

    // Portfolio
    $group->get("/portfolio", "getPortfolio");
    $group->post("/portfolio", "createPortfolio");

    // Clients
    $group->get("/clients", "getClients");
    $group->post("/clients", "createClient");

    // Image Upload
    $group->post("/upload", "uploadImage");
    $group->get("/images", "getImages");
})->add("authMiddleware");

$app->run();
