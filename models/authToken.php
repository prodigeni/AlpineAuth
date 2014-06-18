<?php
//include config for constants
include_once(__DIR__.'/../AlpineAuth.config.php');

//user auth token model
class AuthToken extends Illuminate\Database\Eloquent\Model  {
	
	const AUTH_TOKEN_LIFE_IN_SECONDS = STATEFUL_AUTH_TOKEN_LIFETIME_IN_SECONDS;		//use this to define how long a token is valid
    protected $table = 'user_auth_tokens';
	
	//return lifetime in minutes
	public static function getLifetimeInMinutes()
	{
		$authTokenLifeInMinutes = self::AUTH_TOKEN_LIFE_IN_SECONDS /60;
		return $authTokenLifeInMinutes;
	}
	
	//return lifetime in seconds
	public static function getLifetimeInSeconds()
	{
		return self::AUTH_TOKEN_LIFE_IN_SECONDS;
	}
	
	//return lifetime in days
	public static function getLifetimeInDays()
	{
		$authTokenLifeInDays = self::AUTH_TOKEN_LIFE_IN_SECONDS / 60 / 60 / 24;
		return $authTokenLifeInDays;
	}
	
}

?>