<?php
require_once __DIR__ . '/../functions_auth.php';

// Run the cleanup of expired invalidated JWT tokens
cleanupExpiredInvalidatedTokens();

// Output for cron log (optional)
echo "Expired invalidated JWT tokens cleaned up at " . date('Y-m-d H:i:s') . "\n";