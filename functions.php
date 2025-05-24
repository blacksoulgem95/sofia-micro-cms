<?php

require_once __DIR__ . '/functions_auth.php';
require_once __DIR__ . '/functions_mgmt.php';
require_once __DIR__ . '/functions_public.php';

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
