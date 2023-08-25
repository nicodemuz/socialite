<?php

namespace Socialite\Util\Apple;

use Lcobucci\JWT\Signer;

final class AppleSignerNone implements Signer
{
    public function algorithmId(): string
    {
        return 'none';
    }

    public function sign(string $payload, Signer\Key $key): string
    {
        return '';
    }

    public function verify(string $expected, string $payload, Signer\Key $key): bool
    {
        return $expected === '';
    }
}
