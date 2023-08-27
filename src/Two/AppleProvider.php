<?php

namespace Socialite\Two;

use Firebase\JWT\JWK;
use GuzzleHttp\RequestOptions;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Psr\Http\Message\ResponseInterface;
use Ramsey\Uuid\Uuid;
use Socialite\Util\A;
use Socialite\Util\Apple\AppleSignerInMemory;
use Socialite\Util\Apple\AppleSignerNone;

class AppleProvider extends AbstractProvider
{
    /**
     * The separating character for the requested scopes.
     *
     * @var string
     */
    protected $scopeSeparator = ' ';

    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = [
        'name',
        'email',
    ];

    protected $encodingType = PHP_QUERY_RFC3986;

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl(string $state)
    {
        return $this->buildAuthUrlFromBase('https://appleid.apple.com/auth/authorize', $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return 'https://appleid.apple.com/auth/token';
    }

    /**
     * Get the POST fields for the token request.
     *
     * @param string $code
     * @return array
     */
    protected function getTokenFields(string $code)
    {
        $array = A::add(
            parent::getTokenFields($code),
            'grant_type',
            'authorization_code'
        );
        return A::add(
            $array,
            'access_type',
            'offline'
        );
    }

    public function getAccessTokenResponse(string $code)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Basic ' . base64_encode($this->clientId . ':' . $this->clientSecret)
            ],
            'form_params' => $this->getTokenFields($code),
        ]);
        return json_decode($response->getBody(), true);
    }

    protected function getUserByToken(string $token)
    {
        $this->verify($token);
        $claims = explode('.', $token)[1];

        return json_decode(base64_decode($claims), true);
    }

    public function verify($jwt): bool
    {
        $jwtContainer = Configuration::forSymmetricSigner(
            new AppleSignerNone(),
            AppleSignerInMemory::plainText('')
        );
        $token = $jwtContainer->parser()->parse($jwt);
        $response = $this->getHttpClient()->get('https://appleid.apple.com/auth/keys');
        $data = json_decode((string)$response->getBody(), true);

        $publicKeys = JWK::parseKeySet($data);
        $kid = $token->headers()->get('kid');

        if (isset($publicKeys[$kid])) {
            $publicKey = openssl_pkey_get_details($publicKeys[$kid]->getKeyMaterial());
            $constraints = [
                new SignedWith(new Sha256(), AppleSignerInMemory::plainText($publicKey['key'])),
                new IssuedBy('https://appleid.apple.com'),
                new LooseValidAt(SystemClock::fromSystemTimezone()),
            ];

            try {
                $jwtContainer->validator()->assert($token, ...$constraints);

                return true;
            } catch (RequiredConstraintsViolated $e) {
                throw new InvalidStateException($e->getMessage());
            }
        }

        throw new InvalidStateException('Invalid JWT Signature');
    }

    protected function hasInvalidState()
    {
        $invalidState = parent::hasInvalidState();
        if ($invalidState) {
            $state = $this->getSessionData('Socialite.state');
            parse_str($this->request->getBody(), $body);
            $invalidState = !(strlen($state) > 0 && A::get($body, 'state') === $state);
        }

        return $invalidState;
    }



    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException();
        }
        $response = $this->getAccessTokenResponse($this->getCode());
        $appleUserToken = $this->getUserByToken(
            $token = $response['id_token'] ?? null
        );
        if ($this->usesState()) {
            $state = explode('.', $appleUserToken['nonce'])[1];
            if ($state === $this->request->getAttribute('state')) {
                $this->setSessionData('state', $state);
                $this->setSessionData('state_verify', $state);
            }

            if ($this->hasInvalidState()) {
                throw new InvalidStateException();
            }
        }
        $user = $this->mapUserToObject($appleUserToken);
        return $user->setToken($token)
            ->setRefreshToken(A::get($response, 'refresh_token'))
            ->setExpiresIn(A::get($response, 'expires_in'));
    }

    private function getUserRequest(): array
    {
        $value = $this->request->getAttribute('user');

        if (is_array($value)) {
            return $value;
        }

        $value = trim((string)$value);

        if ($value === '') {
            return [];
        }

        return json_decode($value, true);
    }

    protected function mapUserToObject(array $user): User
    {
        $userRequest = $this->getUserRequest();

        if (isset($userRequest['name'])) {
            $user['name'] = $userRequest['name'];
            $fullName = trim(
                ($user['name']['firstName'] ?? '')
                . ' '
                . ($user['name']['lastName'] ?? '')
            );
        }

        return (new User)->setRaw($user)->map([
            'id' => $user['sub'],
            'name' => $fullName ?? null,
            'email' => A::get($user, 'email'),
        ]);
    }

    public function revokeToken(string $token, string $hint = 'access_token'): ResponseInterface
    {
        return $this->getHttpClient()->post('https://appleid.apple.com/auth/revoke', [
            RequestOptions::FORM_PARAMS => [
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'token' => $token,
                'token_type_hint' => $hint,
            ],
        ]);
    }

    public function refreshToken(string $refreshToken): ResponseInterface
    {
        return $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::FORM_PARAMS => [
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
            ],
        ]);
    }

    protected function getCodeFields($state = null): array
    {
        $fields = parent::getCodeFields($state);
        $fields['response_mode'] = 'form_post';

        if ($this->usesState()) {
            $fields['nonce'] = Uuid::uuid4().'.'.$state;
        }
        return $fields;
    }

    protected function getCode()
    {
        $queryCode = A::get($this->request->getQueryParams(), 'code');
        if ($queryCode !== null) {
            return $queryCode;
        }

        parse_str($this->request->getBody(), $body);
        return A::get($body, 'code');
    }
}
