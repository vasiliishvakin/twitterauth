<?php

/*
 * Abraham Williams (abraham@abrah.am) http://abrah.am
 *
 * The first PHP Library to support OAuth for Twitter's REST API.
 */
namespace TwitterAuth;

use OAuthBase\OAuthSignatureMethodHmacSha1;
use OAuthBase\OAuthConsumer;
use OAuthBase\OAuthUtil;
use OAuthBase\OAuthRequest;

/**
 * Twitter OAuth class
 */
class TwitterAuth
{
    /* Contains the last HTTP status code returned. */
    public $http_code;
    /* Contains the last API call. */
    public $url;
    /* Set up the API root URL. */
    public $host = "https://api.twitter.com/1.1/";
    /* Set timeout default. */
    public $timeout = 30;
    /* Set connect timeout. */
    public $connecttimeout = 30;
    /* Verify SSL Cert. */
    public $ssl_verifypeer = FALSE;
    /* Response format. */
    public $format = 'json';
    /* Decode returned json data. */
    public $decode_json = TRUE;
    /* Contains the last HTTP headers returned. */
    public $http_info;
    /* Set the useragnet. */
    public $useragent = 'TwitterOAuth v0.2.0-beta2';
    /* Immediately retry the API call if the response was not successful. */
    //public $retry = TRUE;

    public $http_header = array();
    public $last_api_call;

    public $get_bearer_token = false;
    public $invalidate_bearer_token = false;
    public $encoded_bearer_credentials;
    public $bearer_access_token;

    /* Set proxy. */
    protected $proxy_host;
    protected $proxy_port;
    protected $proxy_userpwd;

    /**
     * Set API URLS
     */
    function accessTokenURL()
    {
        return 'https://api.twitter.com/oauth/access_token';
    }

    function authenticateURL()
    {
        return 'https://api.twitter.com/oauth/authenticate';
    }

    function authorizeURL()
    {
        return 'https://api.twitter.com/oauth/authorize';
    }

    function requestTokenURL()
    {
        return 'https://api.twitter.com/oauth/request_token';
    }

    function BearerTokenURL()
    {
        return 'https://api.twitter.com/oauth2/token';
    }

    function invalidateBearerTokenURL()
    {
        return 'https://api.twitter.com/oauth2/invalidate_token';
    }

    /**
     * Debug helpers
     */
    function lastStatusCode()
    {
        return $this->http_code;
    }

    function lastStatusHeader()
    {
        return $this->http_header;
    }

    function lastAPICall()
    {
        return $this->last_api_call;
    }

    /**
     * construct TwitterOAuth object
     */
    function __construct($consumer_key, $consumer_secret, $oauth_token = NULL, $oauth_token_secret = NULL)
    {
        $this->sha1_method = new OAuthSignatureMethodHmacSha1();
        $this->consumer = new OAuthConsumer($consumer_key, $consumer_secret);
        if (!empty($oauth_token) && !empty($oauth_token_secret)) {
            $this->token = new OAuthConsumer($oauth_token, $oauth_token_secret);
        } else {
            $this->token = NULL;
        }
    }


    /**
     * Get a request_token from Twitter
     *
     * @returns a key/value array containing oauth_token and oauth_token_secret
     */
    function getRequestToken($oauth_callback)
    {
        $parameters = array();
        $parameters['oauth_callback'] = $oauth_callback;
        $request = $this->oAuthRequest($this->requestTokenURL(), 'GET', $parameters);
        $token = OAuthUtil::parse_parameters($request);
        $this->token = new OAuthConsumer($token['oauth_token'], $token['oauth_token_secret']);
        return $token;
    }

    /**
     * Get the authorize URL
     *
     * @returns a string
     */
    function getAuthorizeURL($token, $sign_in_with_twitter = TRUE)
    {
        if (is_array($token)) {
            $token = $token['oauth_token'];
        }
        if (empty($sign_in_with_twitter)) {
            return $this->authorizeURL() . "?oauth_token={$token}";
        } else {
            return $this->authenticateURL() . "?oauth_token={$token}";
        }
    }

    /**
     * Exchange request token and secret for an access token and
     * secret, to sign API calls.
     *
     * @returns array("oauth_token" => "the-access-token",
     *                "oauth_token_secret" => "the-access-secret",
     *                "user_id" => "9436992",
     *                "screen_name" => "abraham")
     */
    function getAccessToken($oauth_verifier)
    {
        $parameters = array();
        $parameters['oauth_verifier'] = $oauth_verifier;
        $request = $this->oAuthRequest($this->accessTokenURL(), 'GET', $parameters);
        $token = OAuthUtil::parse_parameters($request);
        $this->token = new OAuthConsumer($token['oauth_token'], $token['oauth_token_secret']);
        return $token;
    }

    /**
     * One time exchange of username and password for access token and secret.
     *
     * @returns array("oauth_token" => "the-access-token",
     *                "oauth_token_secret" => "the-access-secret",
     *                "user_id" => "9436992",
     *                "screen_name" => "abraham",
     *                "x_auth_expires" => "0")
     */
    function getXAuthToken($username, $password)
    {
        $parameters = array();
        $parameters['x_auth_username'] = $username;
        $parameters['x_auth_password'] = $password;
        $parameters['x_auth_mode'] = 'client_auth';
        $request = $this->oAuthRequest($this->accessTokenURL(), 'POST', $parameters);
        $token = OAuthUtil::parse_parameters($request);
        $this->token = new OAuthConsumer($token['oauth_token'], $token['oauth_token_secret']);
        return $token;
    }

    /**
     * GET wrapper for oAuthRequest.
     */
    function get($url, $parameters = array())
    {
        $response = $this->oAuthRequest($url, 'GET', $parameters);
        if ($this->format === 'json' && $this->decode_json) {
            return json_decode($response);
        }
        return $response;
    }

    /**
     * POST wrapper for oAuthRequest.
     */
    function post($url, $parameters = array())
    {
        $response = $this->oAuthRequest($url, 'POST', $parameters);
        if ($this->format === 'json' && $this->decode_json) {
            return json_decode($response);
        }
        return $response;
    }

    /**
     * DELETE wrapper for oAuthReqeust.
     */
    function delete($url, $parameters = array())
    {
        $response = $this->oAuthRequest($url, 'DELETE', $parameters);
        if ($this->format === 'json' && $this->decode_json) {
            return json_decode($response);
        }
        return $response;
    }

    /**
     * Format and sign an OAuth / API request
     */
    function oAuthRequest($url, $method, $parameters)
    {
        if (strrpos($url, 'https://') !== 0 && strrpos($url, 'http://') !== 0) {
            $url = "{$this->host}{$url}.{$this->format}";
        }
        $request = OAuthRequest::from_consumer_and_token($this->consumer, $this->token, $method, $url, $parameters);
        $request->sign_request($this->sha1_method, $this->consumer, $this->token);
        switch ($method) {
            case 'GET':
                return $this->http($request->to_url(), 'GET');
            case 'POST':
            default:
                if ($this->get_bearer_token || $this->invalidate_bearer_token) {
                    $post_data = http_build_query($parameters);
                } else {
                    $post_data = $request->to_postdata();
                }
                return $this->http($request->get_normalized_http_url(), $method, $post_data);
        }
    }

    /**
     * Make an HTTP request
     *
     * @param string $url
     * @param string $method
     * @param null $postfields
     * @return OAuthRequest results
     */
    function http($url, $method, $postfields = NULL)
    {
        $this->http_info = array();
        $ci = curl_init();
        /* Curl settings */
        curl_setopt($ci, CURLOPT_USERAGENT, $this->useragent);
        curl_setopt($ci, CURLOPT_CONNECTTIMEOUT, $this->connecttimeout);
        curl_setopt($ci, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ci, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ci, CURLOPT_SSL_VERIFYPEER, $this->ssl_verifypeer);
        curl_setopt($ci, CURLOPT_HEADERFUNCTION, array($this, 'getHeader'));
        curl_setopt($ci, CURLOPT_HEADER, FALSE);

        $this->setHeaders($ci);

        switch ($method) {
            case 'POST':
                curl_setopt($ci, CURLOPT_POST, TRUE);
                if (!empty($postfields)) {
                    curl_setopt($ci, CURLOPT_POSTFIELDS, $postfields);
                }
                break;
            case 'DELETE':
                curl_setopt($ci, CURLOPT_CUSTOMREQUEST, 'DELETE');
                if (!empty($postfields)) {
                    $url = "{$url}?{$postfields}";
                }
        }

        if ($this->proxy_host) {
            curl_setopt($ci, CURLOPT_PROXY, $this->proxy_host);
            curl_setopt($ci, CURLOPT_PROXYPORT, $this->proxy_port);
            curl_setopt($ci, CURLOPT_PROXYUSERPWD, $this->proxy_userpwd);
        }
        //curl_setopt($ci, CURLINFO_HEADER_OUT,true); var_dump($postfields);
        $this->setUrl($ci, $url);
        $response = curl_exec($ci);
        $error = curl_error($ci);
        $this->http_code = curl_getinfo($ci, CURLINFO_HTTP_CODE);
        $this->http_info = array_merge($this->http_info, curl_getinfo($ci));
        curl_close($ci);
        return $response;
    }

    /**
     * Get the header info to store.
     */
    function getHeader($ch, $header)
    {
        $i = strpos($header, ':');
        if (!empty($i)) {
            $key = str_replace('-', '_', strtolower(substr($header, 0, $i)));
            $value = trim(substr($header, $i + 2));
            $this->http_header[$key] = $value;
        }
        return strlen($header);
    }


    /**
     * @link https://dev.twitter.com/docs/auth/application-only-auth
     *
     * @return OAuthRequest|string
     */
    function getBearerToken()
    {
        $this->generateEncodedBearerCredentials();
        $this->bearer_access_token = null;

        $this->get_bearer_token = true;
        $response = $this->post("oauth2/token", array("grant_type" => "client_credentials"));
        $this->get_bearer_token = false;

        if (isset($response->token_type) && $response->token_type == "bearer") {
            return $this->bearer_access_token = urldecode($response->access_token); // Access Token has be url encoding.
        } else {
            return $response;
        }
    }

    /**
     * @param string $bearer_access_token
     */
    function setBearerToken($bearer_access_token)
    {
        $this->generateEncodedBearerCredentials();
        $this->bearer_access_token = $bearer_access_token;
    }

    /**
     * @link https://dev.twitter.com/docs/api/1.1/post/oauth2/invalidate_token
     *
     * @return OAuthRequest|string
     */
    function invalidateBearerToken($bearer_access_token)
    {
        $this->generateEncodedBearerCredentials();
        $this->bearer_access_token = $bearer_access_token;

        $this->invalidate_bearer_token = true;
        $response = $this->post("oauth2/invalidate_token", array("access_token" => $this->bearer_access_token));
        $this->invalidate_bearer_token = false;

        if (isset($response->access_token)) {
            $this->bearer_access_token = null;
            return urldecode($response->access_token);
        } else {
            return $response;
        }
    }

    function generateEncodedBearerCredentials()
    {
        $bearer_credentials = urlencode($this->consumer->key) . ":" . urlencode($this->consumer->secret);

        $this->encoded_bearer_credentials = base64_encode($bearer_credentials);
    }

    protected function setHeaders($ci)
    {
        if ($this->get_bearer_token || $this->invalidate_bearer_token) {
            $this->setBearerCredentialHeaders($ci);
        } elseif ($this->encoded_bearer_credentials && $this->bearer_access_token) {
            $this->setBearerTokenHeaders($ci);
        } else {
            $this->generateHeaders($ci);
        }
    }

    protected function generateHeaders($ci)
    {
        curl_setopt($ci, CURLOPT_HTTPHEADER, array('Expect:'));
    }

    protected function setBearerCredentialHeaders($ci)
    {
        $headers = array(
            "Authorization: Basic " . $this->encoded_bearer_credentials,
            "Content-Type: application/x-www-form-urlencoded;charset=UTF-8"
        );
        curl_setopt($ci, CURLOPT_HTTPHEADER, $headers);
    }

    protected function setBearerTokenHeaders($ci)
    {
        $headers = array("Authorization: Bearer " . urlencode($this->bearer_access_token));
        curl_setopt($ci, CURLOPT_HTTPHEADER, $headers);
    }

    protected function setUrl($ci, $url)
    {
        if ($this->get_bearer_token) {
            $url = $this->BearerTokenURL();
        } elseif ($this->invalidate_bearer_token) {
            $url = $this->invalidateBearerTokenURL();
        }
        curl_setopt($ci, CURLOPT_URL, $url);
        $this->url = $url;
    }

    /**
     * @param string $proxy_host
     * @param int $proxy_port
     * @param string $proxy_username
     * @param string $proxy_password
     */
    function setProxy($proxy_host, $proxy_port = 8080, $proxy_username = '', $proxy_password = '')
    {
        $this->proxy_host = $proxy_host;
        $this->proxy_port = $proxy_port;
        $this->proxy_userpwd = $proxy_username . ":" . $proxy_password;
    }

}
