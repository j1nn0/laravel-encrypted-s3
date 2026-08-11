<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Support;

use League\Flysystem\PathPrefixer;

/**
 * @internal
 */
final class ObjectLocation
{
    private readonly PathPrefixer $prefixer;

    public function __construct(
        private readonly string $bucket,
        private readonly string $root,
    ) {
        $this->prefixer = new PathPrefixer($root);
    }

    public function bucket(): string
    {
        return $this->bucket;
    }

    public function root(): string
    {
        return $this->root;
    }

    public function key(string $path): string
    {
        return $this->prefixer->prefixPath($path);
    }
}
