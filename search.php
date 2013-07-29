<?php
/**
 * GET search/tweets with Application-only authentication test.
 *
 * K.Sasaki <among753@gmail.com>
 * https://github.com/among753/twitteroauth
 *
 */

header("content-type: text/html; charset=utf-8");
/* Start session and load library. */
session_start();

require_once('twitteroauth/twitteroauth.php');
require_once('config.php');
/* Autolink */
require_once('Twitter/Autolink.php');


/* Create a TwitterOauth object with consumer/my application tokens. */
//$connection = new TwitterOAuth(CONSUMER_KEY, CONSUMER_SECRET, OAUTH_TOKEN, OAUTH_TOKEN_SECRET);
$connection = new TwitterOAuth(CONSUMER_KEY, CONSUMER_SECRET);

/* Proxy Setting */
if ( defined('PROXY_HOST') ) $connection->setProxy(PROXY_HOST, PROXY_PORT);

/* Bearer Token invalidate */
if (isset($_GET['invalidate']) && $_GET['invalidate']) {
	// 実際にWebアプリケーションで使用するときは15〜60分でトークンを破棄して新しく取得すること
	$invalidate_bearer_token = $connection->invalidateBearerToken();
	if ( isset($invalidate_bearer_token->errors) ) {
		echo "Bearer Token was not invalidated.".PHP_EOL;
	} else {
		echo "Bearer Token has been invalidate.".PHP_EOL;
	}
	var_dump($invalidate_bearer_token);
	$_SESSION = array();
}

/* OAuth 2 Bearer Token */
if ( empty($_SESSION['bearer_token']) ) {
	// セッションにbearer_tokenを持っていないと取得
	$bearer_token = $connection->getBearerToken();
	/* Save temporary credentials to session. */
	$_SESSION['bearer_token'] = $bearer_token;
} else {
	$connection->setBearerToken( $_SESSION['bearer_token'] );
}

echo "SESSION:<br>".PHP_EOL; var_dump($_SESSION);

echo "GET:<br>".PHP_EOL;var_dump($_GET);
$q = (isset($_GET['q'])) ? $_GET['q'] : "#GitHub";
$param = array(
	"q" => urlencode($q),
	"count" => "5"
);

// $iの最大値を上げると連続してAPIにアクセスするのでrate_limitを使い果たすことができます。
// ただしtwitterAPIに負荷がかかりますので最悪アカウント凍結される場合があります。
// 使用は自己責任でお願いします。
for ($i=0;$i<1;$i++) {
	$result = $connection->get('search/tweets', $param);
	if ( isset($result->errors) ) {
		echo "Error.<br>".PHP_EOL;
		var_dump($result);
		var_dump($connection);
		return;
	}
	echo "Rate Limit:<br>".PHP_EOL; var_dump($connection->http_header['x_rate_limit_remaining']);

	showTweets($result->statuses);

}

function _showTweets($tweets) {
	foreach($tweets as $tweet){
		echo '<li>';
		echo '<p class="twitter_icon"><a href="http://twitter.com/'.$tweet->user->screen_name.'" target="_blank"><img src="'.$tweet->user->profile_image_url.'" alt="icon" width="46" height="46" /></a></p>';
		echo '<div class="twitter_tweet"><p><span class="twitter_content">'.$tweet->text.'</span><span class="twitter_date">'.$tweet->created_at.'</span></p></div>';
		echo "</li>\n";
	}
}

function showTweets($tweets) {
	foreach($tweets as $tweet) {
		$text = Twitter_Autolink::create($tweet->text)
			->setNoFollow(false)
			->addLinks();
		echo '<li>';
		echo '<p class="twitter_icon"><a href="http://twitter.com/'.$tweet->user->screen_name.'" target="_blank"><img src="'.$tweet->user->profile_image_url.'" alt="icon" width="46" height="46" /></a></p>';
		echo '<div class="twitter_tweet"><p><span class="twitter_content">'.$text.'</span><span class="twitter_date">'.$tweet->created_at.'</span></p></div>';
		echo "</li>\n";
	}
}

?>