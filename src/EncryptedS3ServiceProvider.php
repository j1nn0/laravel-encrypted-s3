<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3;

use Illuminate\Support\Facades\Storage;
use Illuminate\Support\ServiceProvider;
use J1nn0\EncryptedS3\Filesystem\EncryptedS3Filesystem;

final class EncryptedS3ServiceProvider extends ServiceProvider
{
    public function register(): void {}

    public function boot(): void
    {
        Storage::extend('encrypted-s3', function ($app, array $config): EncryptedS3Filesystem {
            return (new EncryptedS3DiskFactory)->make($config);
        });
    }
}
