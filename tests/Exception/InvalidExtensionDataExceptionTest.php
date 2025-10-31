<?php

declare(strict_types=1);

namespace Tourze\TLSExtensionTLS13\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSExtensionTLS13\Exception\InvalidExtensionDataException;

/**
 * @internal
 */
#[CoversClass(InvalidExtensionDataException::class)]
final class InvalidExtensionDataExceptionTest extends AbstractExceptionTestCase
{
    public function testIsInstanceOfInvalidArgumentException(): void
    {
        $exception = new InvalidExtensionDataException('Test message');

        $this->assertInstanceOf(\InvalidArgumentException::class, $exception);
    }

    public function testConstructorWithMessage(): void
    {
        $message = 'Invalid extension data provided';
        $exception = new InvalidExtensionDataException($message);

        $this->assertSame($message, $exception->getMessage());
    }

    public function testConstructorWithMessageAndCode(): void
    {
        $message = 'Invalid extension data';
        $code = 100;
        $exception = new InvalidExtensionDataException($message, $code);

        $this->assertSame($message, $exception->getMessage());
        $this->assertSame($code, $exception->getCode());
    }

    public function testConstructorWithPreviousException(): void
    {
        $previous = new \Exception('Previous error');
        $exception = new InvalidExtensionDataException('Test', 0, $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }
}
