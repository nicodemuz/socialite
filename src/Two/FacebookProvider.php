<?php
namespace Socialite\Two;

use Socialite\Util\A;

class FacebookProvider extends AbstractProvider
{
    /**
     * The base Facebook Graph URL.
     *
     * @var string
     */
    protected $graphUrl = 'https://graph.facebook.com';

    /**
     * The Graph API version for the request.
     *
     * @var string
     */
    protected $version = 'v3.0';

    /**
     * The user fields being requested.
     *
     * @var array
     */
    protected $fields = ['name', 'email', 'gender', 'verified', 'link'];

    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = ['email'];

    /**
     * Display the dialog in a popup view.
     *
     * @var bool
     */
    protected $popup = false;

    /**
     * Re-request a declined permission.
     *
     * @var bool
     */
    protected $reRequest = false;

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl(?string $state)
    {
        return $this->buildAuthUrlFromBase('https://www.facebook.com/' . $this->version . '/dialog/oauth', $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return $this->graphUrl . '/' . $this->version . '/oauth/access_token';
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenResponse(string $code)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            'form_params' => $this->getTokenFields($code),
        ]);
        $data = json_decode($response->getBody(), true);
        if (isset($data['expires'])) {
            $data['expires_in'] = $data['expires'];
            unset($data['expires']);
        }

        return $data;
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken(string $token)
    {
        $meUrl = "{$this->graphUrl}/{$this->version}/me?access_token={$token}&fields=" . implode(',', $this->fields);
        if (!empty($this->clientSecret)) {
            $appSecretProof = hash_hmac('sha256', $token, $this->clientSecret);
            $meUrl .= '&appsecret_proof=' . $appSecretProof;
        }
        $response = $this->getHttpClient()->get($meUrl, [
            'headers' => [
                'Accept' => 'application/json',
            ],
        ]);
        return json_decode($response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        $avatarUrl = $this->graphUrl . '/' . $this->version . '/' . $user['id'] . '/picture';
        return (new User)->setRaw($user)->map([
            'id' => $user['id'],
            'nickname' => null,
            'name' => A::get($user, 'name'),
            'email' => A::get($user, 'email'),
            'avatar' => $avatarUrl . '?type=normal',
            'avatar_original' => $avatarUrl . '?width=1920',
            'profileUrl' => A::get($user, 'link'),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getCodeFields($state = null)
    {
        $fields = parent::getCodeFields($state);
        if ($this->popup) {
            $fields['display'] = 'popup';
        }
        if ($this->reRequest) {
            $fields['auth_type'] = 'rerequest';
        }
        return $fields;
    }

    /**
     * Set the user fields to request from Facebook.
     *
     * @param array $fields
     * @return $this
     */
    public function fields(array $fields)
    {
        $this->fields = $fields;
        return $this;
    }

    /**
     * Set the dialog to be displayed as a popup.
     *
     * @return $this
     */
    public function asPopup()
    {
        $this->popup = true;
        return $this;
    }

    /**
     * Re-request permissions which were previously declined.
     *
     * @return $this
     */
    public function reRequest()
    {
        $this->reRequest = true;
        return $this;
    }
}
