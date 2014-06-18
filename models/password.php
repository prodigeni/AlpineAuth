<?php
//user password model
class Password extends Illuminate\Database\Eloquent\Model  {

    protected $table = 'user_passwords';
	protected $primaryKey = 'user_id';
	const LIFE_IN_SECONDS = PASSWORD_LIFETIME_IN_SECONDS;		//use this to define how long a password is valid
	
	//return lifetime in minutes
	public static function getLifetimeInMinutes()
	{
		$password_life_in_minutes = self::LIFE_IN_SECONDS /60;
		return $password_life_in_minutes;
	}
	
	//return lifetime in seconds
	public static function getLifetimeInSeconds()
	{
		return self::LIFE_IN_SECONDS;
	}
	
	//return lifetime in days
	public static function getLifetimeInDays()
	{
		$password_life_in_days = self::LIFE_IN_SECONDS / 60 / 60 / 24;
		return $password_life_in_days;
	}
}

?>