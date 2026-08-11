<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Unit;

use J1nn0\EncryptedS3\Support\ObjectLocation;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ObjectLocationTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function rootProvider(): iterable
    {
        yield 'empty root' => ['', 'rooted.txt'];
        yield 'root prefix' => ['root-prefix', 'root-prefix/rooted.txt'];
        yield 'root prefix with trailing slash' => ['root-prefix/', 'root-prefix/rooted.txt'];
        yield 'nested root prefix' => ['a/b', 'a/b/rooted.txt'];
    }

    #[DataProvider('rootProvider')]
    public function test_key_prefixes_paths_without_changing_path_prefixer_behavior(
        string $root,
        string $expectedKey,
    ): void {
        $location = new ObjectLocation('bucket', $root);

        self::assertSame($expectedKey, $location->key('rooted.txt'));
    }

    public function test_bucket_and_root_return_raw_values(): void
    {
        $location = new ObjectLocation('bucket-name', 'root-prefix/');

        self::assertSame('bucket-name', $location->bucket());
        self::assertSame('root-prefix/', $location->root());
    }
}
