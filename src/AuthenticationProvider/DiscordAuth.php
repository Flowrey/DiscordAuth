<?php

namespace WSOAuth\AuthenticationProvider;

use Wohali\OAuth2\Client\Provider\Discord;
use MediaWiki\User\UserIdentity;

class DiscordAuth extends AuthProvider
{

	/**
	 * @var Discord
	 */
	private $provider;
	private $guildId;

	/**
	 * @inheritDoc
	 */
	public function __construct(
		string $clientId,
		string $clientSecret,
		?string $authUri,
		?string $redirectUri,
		array $extensionData = []
	) {
		$this->provider = new Discord([
			'clientId' => $clientId,
			'clientSecret' => $clientSecret,
			'redirectUri' => $redirectUri
		]);
		$this->guildId = $extensionData[0];
	}

	/**
	 * @inheritDoc
	 */
	public function login(?string &$key, ?string &$secret, ?string &$authUrl): bool
	{
		$authUrl = $this->provider->getAuthorizationUrl(['scope' => ['identify', 'guilds']]);

		$secret = $this->provider->getState();

		return true;
	}

	/**
	 * @inheritDoc
	 */
	public function logout(UserIdentity &$user): void
	{
	}

	/**
	 * @inheritDoc
	 */
	public function getUser(string $key, string $secret, &$errorMessage)
	{
		if (!isset($_GET['code'])) {
			return false;
		}

		if (!isset($_GET['state']) || empty($_GET['state']) || ($_GET['state'] !== $secret)) {
			return false;
		}

		try {
			$token = $this->provider->getAccessToken('authorization_code', ['code' => $_GET['code']]);

			$url = 'https://discord.com/api/users/@me/guilds';
			$options = array(
				'http' => array (
					'header' => "Authorization: Bearer " . $token->getToken() . "\r\n",
					'method' => 'GET'
				)
			);
			$context = stream_context_create($options);
			$result = file_get_contents($url, false, $context);
			if ($result === FALSE) {
				file_put_contents('php://stderr', print_r("failed to get guild information\n", TRUE));
				return false;
			}

			$isGuildMember = False;
			$input = json_decode($result, TRUE);
			foreach ($input as $value) {
				if ($this->guildId === (int)$value["id"]) {
					$isGuildMember = True;
					break;
				}
			}

			if (!$isGuildMember) {
				file_put_contents('php://stderr', print_r("not a guild member\n", TRUE));
				return false;
			}

			$user = $this->provider->getResourceOwner($token);
			return [
				'name' => $user->getId(),
				'realname' => $user->getUsername(),
				'email' => $user->getId() . '@discord.com',
				'isGuildMember' => $isGuildMember,
			];
		} catch (\Exception $e) {
			return false;
		}
	}

	/**
	 * @inheritDoc
	 */
	public function saveExtraAttributes(int $id): void
	{
	}
}