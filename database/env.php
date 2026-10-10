<?php
declare(strict_types=1);
// Non-secret runtime settings and protected directory paths.
return [
    'environment' => 'production',
    'debug' => false,
    'root_dir' => dirname(__DIR__),
    'database_dir' => __DIR__,
    'logs_dir' => __DIR__ . '/logs',
    'backups_dir' => __DIR__ . '/backups',
    'keys_dir' => __DIR__ . '/keys',
    'uploads_dir' => __DIR__ . '/uploads',
];