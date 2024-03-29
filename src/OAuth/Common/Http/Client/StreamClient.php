<?php

namespace OAuth\Common\Http\Client;

use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\UriInterface;

/**
 * Client implementation for streams/file_get_contents
 */
class StreamClient extends AbstractClient
{
    /**
     * Any implementing HTTP providers should send a request to the provided endpoint with the parameters.
     * They should return, in string form, the response body and throw an exception on error.
     *
     * @param UriInterface $endpoint
     * @param mixed        $requestBody
     * @param array        $extraHeaders
     * @param string       $method
     *
     * @return string
     *
     * @throws TokenResponseException
     * @throws \InvalidArgumentException
     */
    public function retrieveResponse(
        UriInterface $endpoint,
        $requestBody,
        array $extraHeaders = array(),
        $method = 'POST'
    ) {
        // Normalize method name
        $method = strtoupper($method);

        $this->normalizeHeaders($extraHeaders);

        if ($method === 'GET' && !empty($requestBody)) {
            throw new \InvalidArgumentException('No body expected for "GET" request.');
        }

        if (!isset($extraHeaders['Content-type']) && $method === 'POST' && is_array($requestBody)) {
            $extraHeaders['Content-type'] = 'Content-type: application/x-www-form-urlencoded';
        }

        $host = 'Host: '.$endpoint->getHost();
        // Append port to Host if it has been specified
        if ($endpoint->hasExplicitPortSpecified()) {
            $host .= ':'.$endpoint->getPort();
        }

        $extraHeaders['Host']       = $host;
        $extraHeaders['Connection'] = 'Connection: close';

        if(is_array($requestBody))
		{
            $requestBody = http_build_query($requestBody, '', '&');
        }
        $extraHeaders['Content-length'] = 'Content-length: '.strlen($requestBody);

        if($endpoint->getAbsoluteUri() == 'https://ssl.reddit.com/api/v1/access_token')
        {
	        $extraHeaders['Authorization'] = "Authorization: Basic " . base64_encode(\Config::get('packages/artdarek/oauth-4-laravel/config.consumers.Reddit.client_id') . ":" . \Config::get('packages/artdarek/oauth-4-laravel/config.consumers.Reddit.secret'));
	    }

		if($endpoint->getAbsoluteUri() == 'https://api.twitch.tv/kraken/user')
		{
			$extraHeaders['Client-ID'] = \Config::get('packages/artdarek/oauth-4-laravel/config.consumers.Twitch.client_id');
		}

        $context = $this->generateStreamContext($requestBody, $extraHeaders, $method);
        #$level = error_reporting(0);
        $response = file_get_contents($endpoint->getAbsoluteUri(), false, $context);
        #error_reporting($level);
        if (false === $response) {
            $lastError = error_get_last();
            if (is_null($lastError)) {
                throw new TokenResponseException('Failed to request resource.');
            }
            throw new TokenResponseException($lastError['message']);
        }

        return $response;
    }

    private function generateStreamContext($body, $headers, $method)
    {
        return stream_context_create(
            array(
                'http' => array(
                    'method'           => $method,
                    'header'           => implode("\r\n", array_values($headers)),
                    'content'          => $body,
                    'protocol_version' => '1.1',
                    'user_agent'       => $this->userAgent,
                    'max_redirects'    => $this->maxRedirects,
                    'timeout'          => $this->timeout
                ),
            )
        );
    }
}
