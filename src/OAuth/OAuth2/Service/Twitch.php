<?php

	namespace OAuth\OAuth2\Service;
	
	use OAuth\OAuth2\Token\StdOAuth2Token;
	use OAuth\Common\Http\Exception\TokenResponseException;
	use OAuth\Common\Http\Uri\Uri;
	use OAuth\Common\Consumer\CredentialsInterface;
	use OAuth\Common\Http\Client\ClientInterface;
	use OAuth\Common\Storage\TokenStorageInterface;
	use OAuth\Common\Http\Uri\UriInterface;
	
	class Twitch extends AbstractService
	{
		/**
		 * Defined scopes
		 *
		 * @link https://github.com/justintv/Twitch-API/blob/master/authentication.md
		 */
		const SCOPE_USER_READ						= 'user_read'; // Read access to non-public user information, such as email address.
		const SCOPE_USER_BLOCKS_EDIT				= 'user_blocks_edit'; // Ability to ignore or unignore on behalf of a user.
		const SCOPE_USER_BLOCKS_READ				= 'user_blocks_read'; // Read access to a user's list of ignored users.
		const SCOPE_USER_FOLLOWS_EDIT				= 'channel_read'; // Access to manage a user's followed channels.
		const SCOPE_CHANNEL_READ					= 'channel_read'; // Read access to non-public channel information, including email address and stream key.
		const SCOPE_CHANNEL_EDITOR					= 'channel_editor'; // Write access to channel metadata (game, status, etc).
		const SCOPE_CHANNEL_COMMERCIAL				= 'channel_commercial'; // Access to trigger commercials on channel.
		const SCOPE_CHANNEL_STREAM					= 'channel_stream'; // Ability to reset a channel's stream key.
		const SCOPE_CHANNEL_SUBSCRIPTIONS			= 'channel_subscriptions'; // Read access to all subscribers to your channel.
		const SCOPE_USER_SUBSCRIPTIONS				= 'user_subscriptions'; // Read access to subscriptions of a user.
		const SCOPE_CHANNEL_CHECK_SUBSCRIPTION		= 'channel_check_subscription'; // Read access to check if a user is subscribed to your channel.
		const SCOPE_CHAT_LOGIN						= 'chat_login'; // Ability to log into chat and send messages.

		/**
		 * Construct
		 */	
		public function __construct(CredentialsInterface $credentials, ClientInterface $httpClient, TokenStorageInterface $storage, $scopes = array(), UriInterface $baseApiUri = null)
		{
			parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri, true);

			if(null === $baseApiUri)
			{
				$this->baseApiUri = new Uri('https://api.twitch.tv/kraken/');
			}
		}

		/**
		 * {@inheritdoc}
		 */
		public function getAuthorizationEndpoint()
		{
			return new Uri('https://api.twitch.tv/kraken/oauth2/authorize');
		}
	
		/**
		 * {@inheritdoc}
		 */
		public function getAccessTokenEndpoint()
		{
			return new Uri('https://api.twitch.tv/kraken/oauth2/token');
		}
	
		/**
		 * {@inheritdoc}
		 */
		protected function getAuthorizationMethod()
		{
			return static::AUTHORIZATION_METHOD_HEADER_OAUTH;
		}
	
		/**
		 * {@inheritdoc}
		 */
		protected function parseAccessTokenResponse($responseBody)
		{
			$data = json_decode($responseBody, true);
			
			if(null === $data || !is_array($data))
			{
				throw new TokenResponseException('Unable to parse response.');
			}else if(isset($data['error'])){
				throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
			}

			$token = new StdOAuth2Token();
			$token->setAccessToken($data['access_token']);
			$token->setLifeTime(3600);
	
			if(isset($data['refresh_token']))
			{
				$token->setRefreshToken($data['refresh_token']);
				unset($data['refresh_token']);
			}
	
			unset($data['access_token']);
	
			$token->setExtraParams($data);
	
			return $token;
		}
	
		/**
		 * {@inheritdoc}
		 */
		/*protected function getExtraOAuthHeaders()
		{
			// Reddit uses a Basic OAuth header
			return array('Authorization' => 'Basic ' .
				base64_encode($this->credentials->getConsumerId() . ':' . $this->credentials->getConsumerSecret()));
		}*/
	}
