<?php
/*
*		AlpineAuth's Main Configuration File.
*		
*/
//database connection configuration
define('DB_DRIVER', 'mysql');
define('DB_HOST', 'localhost');
define('DB_DATABASE', 'AlpineAuth');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', '');
define('DB_CHARSET', 'utf8');
define('DB_COLLATION', 'utf8_general_ci');
define('DB_PREFIX','');

//auth token settings. use stateful auth tokens, stateless auth tokens, or both
define('USE_STATEFUL_AUTH_TOKEN', true);
define('USE_STATELESS_AUTH_TOKEN', true);

//whether to use sessions for storing temporary user data (username, userid, permission) for browser users, or only pull from cookies
define('USE_SESSION_FOR_BROWSER_USER_DATA', true);

//enable or disable BruteForceBlocker brute force attack prevention
define('USE_BRUTE_FORCE_PREVENTION',true);

//define whether or not to require account activation via email
define('REQUIRE_EMAIL_ACTIVATION', true);
//define email settings
define('EM_SERVICE_NAME','AlpineAuth');						//this is the name of your company, website, app, or game
define('EM_SENDER_ADDRESS','noreply@AlpineAuth.com');		//address emails are sent from
define('ENCRYPT_USER_EMAIL_ADDRESSES', true);
//define required URLs for redirecting in emails
define('PASSWORD_RESET_REDIRECT','http://localhost/AlpineAuth/demos/browserDemo/passwordReset.php');
define('ACCOUNT_ACTIVATION_REDIRECT','http://localhost/AlpineAuth/demos/browserDemo/accountActivation.php');

//define cookie storage information
define('COOKIE_PATH', '/');	
define('COOKIE_DOMAIN', null);
define('COOKIE_LIFETIME_IN_SECONDS',2592000);

//define authentication token lifetimes
define('STATEFUL_AUTH_TOKEN_LIFETIME_IN_SECONDS',2592000);
define('PASSWORD_RESET_TOKEN_LIFETIME_IN_SECONDS',86400);

//define password options
define('PASSWORD_AUTO_EXPIRE', true);
define('PASSWORD_LIFETIME_IN_SECONDS',15552000);	//default 15552000 (6 months)
define('PASSWORD_HASH_COST', 10);	//variable cpu cost of password hashing. ranges from 4 to 31

//define single stateful user mode
//if set to true, this ensures that an account can only ever have one person using it at a time if stateful auth tokens are enabled, as older auth tokens are destroyed when a new one is created (when a user logs in). this is not possible with stateless auth tokens
define('SINGLE_STATEFUL_USER_MODE', false);

//define cryptographic sensitive information
@define('STATELESS_AUTH_TOKEN_KEY', 'put your key here');	//key used for hashing and verifying stateless auth tokens
@define('STATELESS_AUTH_TOKEN_SECRET', 'put your secret here');	//arbitrary secret value necessary for recreating and verifying stateless auth tokens (signed token)
@define('ENCRYPTED_EMAIL_SECRET', 'put your secret here');	//secret for encrypted signed email address storage with HMAC
@define('ENCRYPTED_COOKIE_STORAGE_SECRET', 'put your secret here');	//secret for signed cookie storage with HMAC
@define('GENERAL_ENCRYPTION_SECRET','put your secret here');	//secret for when using general public encrypt() and decrypt() methods
?>