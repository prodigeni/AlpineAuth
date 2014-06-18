<?php
/*
*		AlpineAuth 0.1
*		PHP User Authentication and management library for both typical website authentication and remote authentication on clients not installed on
*		the server (such as mobile applications).
*		By Evan Francis, 2014
*		==LICENSE==
*		
*/
//grab config file
require_once(__DIR__.'/AlpineAuth.config.php');
//start session if needed
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}
class AlpineAuth{
	
	//flash message keys for each method. flash messages are key values pairs that are temporarily stored in session using the FlashMessage class, used for getting error messages from previously called methods
	private static $createUserFlashMessages = ["create_user_create_error", "create_user_save_error", "create_user_password_save_error", "create_user_empty_email_error","create_user_empty_username_error","create_user_empty_password_error"];
	private static $authenticateUserFlashMessages = ["authenticate_user_error", "authenticate_user_username_error","authenticate_user_rehash_password_error"];
	private static $logInFlashMessages = ["login_user_save_error", "login_token_create_error", "login_token_save_error", "login_user_authenticate_error","login_activated_error","login_password_expired_error","login_bfb_add_error","login_bfb_catpcha","login_bfb_delay","login_bfb_error"];
	private static $logOutFlashMessages = ["logout_user_status_error", "logout_user_save_status_error"];
	private static $authenticateStatefulAuthTokenFlashMessages = ["authenticate_token_expired_error","authenticate_token_expired_loggedin_error"];
	private static $removeUserFlashMessages = ["remove_user_error"];
	private static $authenticateStatelessAuthTokenFlashMessages = ["verify_stateless_token_field_error","verify_stateless_token_expired_error","verify_stateless_token_hash_error"];
	private static $verifyUserFlashMessages = ["verify_user_error"];
	private static $splitUserDataFlashMessages = ["split_user_data_data_error"];
	private static $authenticateUserByStatefulAuthTokenFlashMessages = ["authenticate_user_by_stateful_token_error","authenticate_user_by_stateful_token_user_exist_error","authenticate_user_by_stateful_token_token_exist_error"];
	private static $modifyUserFlashMessages = ["modify_user_save_error", "modify_user_empty_name_error"];
	private static $sendMailFlashMessages = ["send_mail_error","send_mail_address_error"];
	private static $generateUserPasswordResetTokenFlashMessages = ["generate_password_reset_token_save_error"];
	private static $sendUserPasswordResetEmailFlashMessages = ["send_user_password_reset_email_address_error"];
	private static $authenticateUserPasswordResetTokenFlashMessages = ["authenticate_user_password_reset_token_exist_error","authenticate_user_password_reset_token_userid_error","authenticate_user_password_reset_token_token_error", "authenticate_user_password_reset_token_expired_error"];
	private static $resetUserPasswordFlashMessages = ["reset_user_password_save_error", "reset_user_password_token_activated_error", "reset_user_password_update_activated_error"];
	private static $setSecureCookieFlashMessages = ["set_secure_cookie_save_error"];
	private static $fetchSecureCookieFlashMessages = ["fetch_secure_cookie_altered_error", "fetch_secure_cookie_exists_error"];
	private static $activateUserFlashMessages = ["activate_user_save_error","activate_user_code_error"];
	private static $setUserPermissionLevelFlashMessages = ["set_user_permission_level_save_error","set_user_permission_level_numeric_error","set_user_permission_level_admin_error"];
	private static $checkFormSpamFlashMessages = ["check_form_spam_set_error","check_form_spam_referer_error"];
	private static $modifyUserBrowserFlashMessages = ["modify_user_browser_error"];
	private static $registerNewUserFlashMessages = ["register_new_user_email_error","register_new_user_email_used_error"];
	private static $logOutUserRemoteFlashMessages = ["log_out_user_remote_decrypt_secure_user_data_error","log_out_user_remote_user_match_error"];
	private static $getBruteForceBlockStatusFlashMessages = ["get_login_brute_force_blocker_enabled_error"];
	private static $modifyUserRemoteFlashMessages = ["modify_user_remote_decrypt_secure_user_data_error","modify_user_user_remote_user_match_error"];
	private static $setUserPermissionLevelRemoteFlashMessages = ["set_user_permission_level_remote_decrypt_secure_user_data_error","set_user_permission_level_user_remote_user_match_error"];
	private static $authenticateRemoteUserFlashMessages = ["authenticate_remote_user_name_error"];
	private static $decryptEmailAddressFlashMessages = ["decrypt_email_error"];
	private static $decryptGeneralFlashMessages = ["decrypt_general_error"];
	
	//request mode, either 'browser' or 'remote'. decides type of error storage
	private $request_mode;
	private $errors;	//array for errors, used when request_mode = 'remote'
	
	//constructur
	function __construct() {
		//include required files
		$this->_includes();
		
		//default request_mode to browser
		$this->request_mode = 'browser';
		$this->errors = array();
	}
   
	//include required files
	private function _includes(){
		//include model for database connection
		require_once( __DIR__.'/models/database.php' );
		//include models for database tables
		require_once( __DIR__.'/models/user.php');
		require_once( __DIR__.'/models/password.php');
		require_once( __DIR__.'/models/authToken.php');
		require_once( __DIR__.'/models/passwordResetToken.php');
		//include helpers
		require_once( __DIR__.'/helpers/flashMessage.php' );						//for creating flash messages
		require_once( __DIR__.'/helpers/RandomValue.php' );							//for generating crypto-secure random values
		require_once( __DIR__.'/helpers/MrClayCookieStorage/CookieStorage.php' );	//for storing cookies that are encrypted and signed with HMAC
		require_once( __DIR__.'/helpers/password.php');								//for compatibility with PHP >=5.5 password_* hash functions
		if(USE_BRUTE_FORCE_PREVENTION){
			require_once( __DIR__.'/helpers/BruteForceBlock.php');					//for prevention of brute force attacks
		}
		
	}
	//sets an internal error
	private function _setError($name, $value){
		//set error according to request_mode
		switch($this->request_mode){
			case 'browser':
				FlashMessage::flash( $name, $value);
				break;
			case 'remote':
				$this->errors[$name] = $value;
				break;
		}
	}
	//gets all the flash messages and returns as array
	public function getErrors(){
		//if remote, return array
		if($this->request_mode == 'remote'){
			$temp_errors = $this->errors;
			$this->errors = array();
			//return array or false if empty
			if(count($temp_errors) == 0){
				return false;
			}else{
				return $temp_errors;
			}
		}
		//if browser, get flash errors from session to return
		else if($this->request_mode == 'browser'){
			//combine all flash message keys into one array
			$all_flash_message_keys = array_merge(
				self::$createUserFlashMessages, 
				self::$removeUserFlashMessages,
				self::$logInFlashMessages,
				self::$logOutFlashMessages,
				self::$authenticateUserFlashMessages,
				self::$authenticateStatefulAuthTokenFlashMessages,
				self::$authenticateStatelessAuthTokenFlashMessages,
				self::$verifyUserFlashMessages,
				self::$splitUserDataFlashMessages,
				self::$authenticateUserByStatefulAuthTokenFlashMessages,
				self::$modifyUserFlashMessages,
				self::$sendMailFlashMessages,
				self::$generateUserPasswordResetTokenFlashMessages,
				self::$sendUserPasswordResetEmailFlashMessages,
				self::$authenticateUserPasswordResetTokenFlashMessages,
				self::$resetUserPasswordFlashMessages,
				self::$setSecureCookieFlashMessages,
				self::$fetchSecureCookieFlashMessages,
				self::$activateUserFlashMessages,
				self::$setUserPermissionLevelFlashMessages,
				self::$checkFormSpamFlashMessages,
				self::$modifyUserBrowserFlashMessages,
				self::$registerNewUserFlashMessages,
				self::$logOutUserRemoteFlashMessages,
				self::$getBruteForceBlockStatusFlashMessages,
				self::$modifyUserRemoteFlashMessages,
				self::$setUserPermissionLevelRemoteFlashMessages,
				self::$authenticateRemoteUserFlashMessages,
				self::$decryptEmailAddressFlashMessages,
				self::$decryptGeneralFlashMessages
			);
			
			//create array to hold errors
			$allErrors = [];
			
			$count = 0;
			//grab each flash message and store in array
			foreach($all_flash_message_keys as $key){
				//get this flash message
				$this_error = FlashMessage::flash($key);
				if($this_error !== null){
					//add this message to allErrors array
					$allErrors[$key] = $this_error;
					$count ++;
				}
			}
			
			//if no errors found, return false
			if($count == 0)
				return false;
			
			return $allErrors;
		}
	}

	/*  =============================================================
				CORE AUTHORIZATION / USER MANAGEMENT METHODS
		=============================================================
	*/
	//attempt to log in a user. updates database and generates auth token(s)
	//captcha is optional, for brute force blocker protection. if the user just answered a correct captcha as required, set as true
	//throttle settings is optional for brute force blocker, if not set default BruteForceBlock settings assumed
	private function _logInUser($user_name, $user_password, $captcha = false, $throttle_settings = null){
		//check failed logins if USE_BRUTE_FORCE_PREVENTION is enabled
		if( USE_BRUTE_FORCE_PREVENTION ){
			//check status of BruteForceBlock
			$BFBresponse = BruteForceBlock::getLoginStatus($throttle_settings);
			//respond to status. if error or delay, return out with message
			switch ($BFBresponse['status']){
				case 'safe':
					//no brute force detected, or required time delay has passed
					break;
				case 'error':
					//error message
					$this->_setError("login_bfb_error",  "BruteForceBlock error:".$BFBresponse['message']);
					return false;
				case 'delay':
					//time delay required
					$this->_setError("login_bfb_delay",  "You must wait ".$BFBresponse['message']." seconds before logging in again.");
					return false;
				case 'captcha':
					//captcha required. if it wasn't marked as correct via optional parameter, return false. require user to solve captcha
					if($captcha !== true){
						$this->_setError("login_bfb_catpcha",  "CAPTCHA required.");
						return false;
					}
					break;
				
			}

		}
		//check if user credentials authenticate
		if($this->authenticateUser($user_name,$user_password)){
			//get this user
			$this_user = $this->getUserObject($user_name);
			
			//check if account requires email activation
			if( REQUIRE_EMAIL_ACTIVATION ){
				if($this_user->activated == false){
					//needs to be activated
					$this->_setError("login_activated_error",  "Account requires activation via email.");
					return false;
				}
			}
			
			//check if password is expired (if enabled)
			if( PASSWORD_AUTO_EXPIRE ){
				//get password info
				$this_user_password = $this->getUserPasswordInfoObject($this_user->id);
				$password_last_reset = strtotime($this_user_password->last_reset);
				
				//check if password is expired yet
				if ($password_last_reset < (time() - PASSWORD_LIFETIME_IN_SECONDS)) {
				   //This user's password is expired, sending reset email
				   $this->_setError("login_password_expired_error",  "Password is expired, a password reset email has been sent.");
				   $this->sendUserPasswordResetEmail($user_name);
				   return false;
				} else {
				   //The password is not expired
				}
			}
			
			//==check what auth tokens should be generated (stateful or stateless)
			//make stateful auth token if set to
			$stateful_auth_token = "";
			if(USE_STATEFUL_AUTH_TOKEN){
				//get user info for auth token
				$this_user_id = $this_user->id;
				
				//get user's password info (hash) for auth token
				$this_ph = Password::where('user_id',$this_user_id)->first();
				$this_user_password_hash = $this_ph->password;
				
				//generate the stateful auth token with the credentials provided
				$stateful_auth_token = $this->_generateStatefulAuthToken($user_name,$this_user_id,$this_user_password_hash);
				if($stateful_auth_token == null){
					//set flash warning to "could not generate user auth token"
					$this->_setError("login_token_create_error",  "Could not generate a stateful auth token.");
					return false;
				}
				
				//if set to single user mode, remove an previously existing tokens with this user_id. 
				//this ensures that an account can only ever have one machine using it at a time
				if(SINGLE_STATEFUL_USER_MODE){
					$tokens_to_remove = AuthToken::where('user_id',$this_user_id)->delete();
				}

				//store the new stateful auth token for this user
				$new_token = new AuthToken;
				$new_token->token = $stateful_auth_token;
				$new_token->user_id = $this_user_id;
				if(!$new_token->save()){
					//set flash warning to "could not save new auth token to database"
					$this->_setError("login_token_save_error",  "Could not save new stateful auth token to database.");
					return false;
				}
				
			}
			
			//make stateless auth token if set to
			$stateless_auth_token = "";
			if(USE_STATELESS_AUTH_TOKEN){
				//build data string for csrf. include auth token for this session, to ensure the token is unique to the appropriate session
				$user_data_string = $user_name.".".STATELESS_AUTH_TOKEN_SECRET;
				$stateless_auth_token = $this->_generateStatelessAuthToken($user_name,AuthToken::getLifetimeInSeconds());
			}
			
			//update database logged_in status for this user
			//set logged in status to true
			$this_user->logged_in = 1;
			//attempt to update in database
			if(!$this_user->save()){
				//set flash warning to "couldn't set logged_in status to true"
				$this->_setError("login_user_save_error",  "Couldn't update user's logged_in status in database.");
				return false;
			}
			
			//return t/f, tokens
			$returnArray = array();
			$returnArray['success'] = true;
			$returnArray['stateful_auth_token'] = $stateful_auth_token;
			$returnArray['stateless_auth_token'] = $stateless_auth_token;
			return $returnArray;
		}else{
			//user didn't authenticate, set flash errors
			//set flash warning
			$this->_setError("login_user_authenticate_error",  "User's credentials couldn't authenticate.");			
			
			//get this user
			$this_user = $this->getUserObject($user_name);
			
			//record failed logins if USE_BRUTE_FORCE_PREVENTION is enabled
			if( USE_BRUTE_FORCE_PREVENTION ){
				//add failed login attempt
				$remote_ip = $_SERVER['REMOTE_ADDR'];
				//if user id doesn't exist (non-existant username was given), set it to -1
				if($this_user == false){
					$this_user_id = -1;
				}else{
					$this_user_id = $this_user->id;
				}
				$BFBresponse = BruteForceBlock::addFailedLoginAttempt($this_user_id, $remote_ip);
				if($BFBresponse !== true){
					//set flash message with bfb error response
					$this->_setError("login_bfb_add_error", "Couldn't add failed login attempt to database for BruteForceBlock, error: ".$BFBresponse );
					return false;
				}
				
			}
			
			//return false
			return false;
		}
	}
	//attempt to log out a user. updates database
	private function _logOutUser($user_name){	
		//get reference to this user
		$this_user = $this->getUserObject($user_name);
		
		if($this_user === false)
			return false;
			
		//update database
		//set user's logged in status to false
		$this_user->logged_in = false;
		if(!$this_user->save()){
			//flash warning to "could not set user logged_in status to false"
			$this->_setError("logout_user_save_status_error",  "Couldn't update user's logged_in status in database.");
			return false;
		}else{
			return true;
		}
	}
	
	//authenticate tokens according to settings. will do stateful, stateless, or both
	public function authenticateTokens($user_name, $stateful_auth_token, $stateless_auth_token){
		//check which token(s) to authenticate (stateful or stateless)
		if(USE_STATEFUL_AUTH_TOKEN){
			//authenticate stateful token
			if(!$this->_authenticateStatefulAuthToken($user_name, $stateful_auth_token)){
				//failed to authenticate, return false
				return false;
			}
		}
		if(USE_STATELESS_AUTH_TOKEN){
			//authenticate stateless auth token
			if(!$this->_authenticateStatelessAuthToken( $user_name, $stateless_auth_token )){
				//failed to authenticate, return false
				return false;
			}
		}
		//if user->logged_in in database is false, update to true
		$this_user = $this->getUserObject($user_name);
		//set logged in status to true
		/*$this_user->logged_in = 1;
		//attempt to update in database
		if(!$this_user->save()){
			//set flash warning to "couldn't set logged_in status to true"
			$this->_setError("login_user_save_error",  "Couldn't update user's logged_in status in database.");
			return false;
		}*/
			
		
		//token(s) authenticated successfully. return true
		return true;		
	}
	
	//create a new user
	private function _createUser($username,$plaintext_password,$email){
		//make sure username, email, and password aren't empty
		if($username == ''){
			//set flash warning
			$this->_setError("create_user_empty_username_error",  "User name required.");
			return false;
		}
		if($plaintext_password == ''){
			//set flash warning
			$this->_setError("create_user_empty_password_error",  "User password required.");
			return false;
		}
		if(REQUIRE_EMAIL_ACTIVATION && $email == ''){
			//set flash warning
			$this->_setError("create_user_empty_email_error",  "User email required.");
			return false;
		}
		
		
		//make sure this username isn't taken
		$this_name_count = User::where('name',$username)->count();
		if($this_name_count > 0){
			//set flash warning to "could not save new user to database"
			$this->_setError("create_user_create_error",  "User name already exists.");
			return false;
		}
		//instance of random value
		$randomValue = new RandomValue;
		//build new user
		$user = new User;
		$user->name = $username;
		//check if email should be encrypted
		if( ENCRYPT_USER_EMAIL_ADDRESSES ){
			//attempt to encrypt
			$encrypted_email = $this->_encryptEmailAddress($username,$email);
			//return false if failure
			if($encrypted_email == false)
				return false;
			$user->email = $encrypted_email;
		}else{
			$user->email = $email;
		}
		$user->activation_code = $randomValue->randomTextString(10);
		
		//save new user
		if(!$user->save()){
			//set flash warning to "could not save new user to database"
			$this->_setError("create_user_save_error",  "Could not save new user to database.");
			return false;
		}
		
		//get user id created
		$user_id = $user->id;
		
		//store password for user
		$user_pass = new Password;
		$user_pass->user_id = $user_id;
		$user_pass->password = $this->_hashPassword($plaintext_password);
		$user_pass->last_reset = date('Y-m-d H:i:s');
		if(!$user_pass->save()){
			//set flash warning to "could not save new user's password to database"
			$this->_setError("create_user_password_save_error",  "Could not save new user's password to database.");
			return false;
		}else{
			return true;
		}
		
	}
	//removes a user from the database
	private function _removeUser($username,$user_pass){
		//get this user
		$this_user = User::where('name',$username)->first();
		
		//verify user existence first
		if(!$this->verifyUser($username)){
			//user doesn't exist
			return false;
		}
		
		//authenticate user credentials
		if(!$this->authenticateUser($username, $user_pass))
			return false;
		
		//attempt to delete uesr from database
		if($this_user->delete()){
			return true;
		}else{
			//set flash warning to "could not delete user"
			$this->_setError("remove_user_error",  "Could not remove user.");
			return false;
		}
	}
	//modify a user's information in the database
	private function _modifyUser($user_name, $new_info_array){
		//check if new user name is blank
		if(isset($new_info_array['name']) && $new_info_array['name'] == ""){
			//set flash warning 
			$this->_setError("modify_user_empty_name_error",  "Could not update user's information. Name cannot be empty.");
			return false;
		}
		
		//check if user is valid
		if(!$this->verifyUser($user_name)){
			return false;
		}
		
		//get this user object
		$this_user = $this->getUserObject($user_name);
		
		//update user in database with new info key->value pairs
		foreach($new_info_array as $new_info_key => $new_info_value){
			//if setting email, check if need to encrypt
			if( $new_info_key == 'email'){
				if( ENCRYPT_USER_EMAIL_ADDRESSES ){
					//encrypt email
					$this_user->$new_info_key = $this->_encryptEmailAddress($user_name, $new_info_value);
				}else{
					//store regular email
					$this_user->$new_info_key = $new_info_value;
				}
			}else{
				//set regular value
				$this_user->$new_info_key = $new_info_value;
			}
		}
		
		if(!$this_user->save()){
			//set flash warning 
			$this->_setError("modify_user_save_error",  "Could not update user's information. Check data types and column names (new info array keys).");
			return false;
		}else{
			return true;
		}
	}

	//verifies whether or not a user is valid (exists)
	public function verifyUser($user_name){
		//get this user id from user object
		$this_user_id = $this->getUserID($user_name);
		
		//check if this user exists
		if($this_user_id !== false){
			return true;
		}else{
			$this->_setError("verify_user_error",  "User '$user_name' doesn't exist." );
			return false;
		}
	}

	//get the user_id associated with a username
	public function getUserID($user_name){
		//get this user id from user object
		$this_user = User::where('name',$user_name)->first();
		@$this_user_id = $this_user->id;		//suppress warning if non-existant
		
		//check if this user exists
		if($this_user_id !== null){
			return $this_user_id;
		}else{
			return false;
		}
	}
	//get the user_name associated with a user_id
	public function getUserName($user_id){
		//get user name
		$this_user = User::where('id',$user_id)->first();
		@$this_user_name = $this_user->name;
		
		//check if username exists
		if($this_user_name !== null){
			return $this_user_name;
		}else{
			return false;
		}
	}
	//get the email associated with a user_name
	public function getUserEmail($user_name){
		//get user name
		$this_user = User::where('name',$user_name)->first();
		$this_user_email = '';
		//check if need to decrypt
		if( ENCRYPT_USER_EMAIL_ADDRESSES) {
			@$this_user_email = $this->_decryptEmailAddress($user_name,$this_user->email);
		}else{
			@$this_user_email = $this_user->email;
		}
		//check for failure of decryption
		if($this_user_email == false)
			return false;
		
		//check if user email exists
		if($this_user_email !== null){
			return $this_user_email;
		}else{
			return false;
		}
	}
	//get user password info from database (entire row).
	public function getUserPasswordInfoObject($user_id){
		//get this user's password number
		$this_password = Password::where('user_id',$user_id)->first();
		
		return $this_password;
	}
	//get user password number.
	public function getUserPasswordNumber($user_id){
		//get this user's password number
		$this_password = Password::where('user_id',$user_id)->first();
		$this_password_number = $this_password->number;
		
		return $this_password_number;
	}

	//split decrypted secure user data into pieces
	private function _splitUserData($user_data){
		//split user data into pieces
		$user_data_pieces = explode('|',$user_data);
		if(count($user_data_pieces) !== 5){
			$this->_setError("split_user_data_data_error",  "User data incomplete or incorrect." );
			return false;
		}
		$user_name = $user_data_pieces[0];
		$user_id = $user_data_pieces[1];
		$user_permission = $user_data_pieces[2];
		$stateful_auth_token = $user_data_pieces[3];
		$stateless_auth_token = $user_data_pieces[4];
		if($user_name == false){
			return false;
		}else{
			//build return array
			$return_array = array();
			$return_array['user_name'] = $user_name;
			$return_array['user_id'] = $user_id;
			$return_array['user_permission'] = $user_permission;
			$return_array['stateful_auth_token'] = $stateful_auth_token;
			$return_array['stateless_auth_token'] = $stateless_auth_token;
			return $return_array;
		}
	}
	//get the stateful auth token of the current logged in user
	private function _getCurrentUserStatefulAuthToken(){
		//check if set to use session
		if( USE_SESSION_FOR_BROWSER_USER_DATA ){
			//return if set in session
			if(isset($_SESSION['AA_stateful_auth_token'])){
				return $_SESSION['AA_stateful_auth_token'];
			}
		}
		//check if username set in cookie
		$user_data = $this->_fetchSecureCookie('AA_user_data');
		//return false if not set
		if($user_data == false)
			return false;
			
		//split user data into pieces
		$user_data_pieces = explode('|',$user_data);
		$user_stateful_auth_token = $user_data_pieces[3];
		
		//set in session if required
		if( USE_SESSION_FOR_BROWSER_USER_DATA ){
			$_SESSION['AA_stateful_auth_token'] = $user_stateful_auth_token;
		}
		//return
		if($user_stateful_auth_token !== false){
			return $user_stateful_auth_token;
		}else{
			return false;
		}
	}
	//get the stateless auth token of the current logged in user
	private function _getCurrentUserStatelessAuthToken(){
		//check if set to use session
		if( USE_SESSION_FOR_BROWSER_USER_DATA ){
			//return if set in session
			if(isset($_SESSION['AA_stateless_auth_token'])){
				return $_SESSION['AA_stateless_auth_token'];
			}
		}
		//check if username set in cookie
		$user_data = $this->_fetchSecureCookie('AA_user_data');
		//return false if not set
		if($user_data == false)
			return false;
			
		//split user data into pieces
		$user_data_pieces = explode('|',$user_data);
		$user_stateless_auth_token = $user_data_pieces[4];
		
		//set in session if required
		if( USE_SESSION_FOR_BROWSER_USER_DATA ){
			$_SESSION['AA_stateless_auth_token'] = $user_stateless_auth_token;
		}
		//return
		if($user_stateless_auth_token !== false){
			return $user_stateless_auth_token;
		}else{
			return false;
		}
	}
	//get the username of the current logged in user
	public function getCurrentUserNameBrowser(){
		//check if set to use session
		if( USE_SESSION_FOR_BROWSER_USER_DATA ){
			//return if set in session
			if(isset($_SESSION['AA_user_name'])){
				return $_SESSION['AA_user_name'];
			}
		}
		//check if username set in cookie
		$user_data = $this->_fetchSecureCookie('AA_user_data');
		//return false if not set
		if($user_data == false)
			return false;
			
		//split user data into pieces
		$user_data_pieces = explode('|',$user_data);
		$user_name = $user_data_pieces[0];
		//set in session if required
		if( USE_SESSION_FOR_BROWSER_USER_DATA ){
			$_SESSION['AA_user_name'] = $user_name;
		}
		//return
		if($user_name !== false){
			return $user_name;
		}else{
			return false;
		}
	}
	//get the user ID of the current logged in user
	public function getCurrentUserIDBrowser(){
		//check if set to use session
		if( USE_SESSION_FOR_BROWSER_USER_DATA ){
			//return if set in session
			if(isset($_SESSION['AA_user_id'])){
				return $_SESSION['AA_user_id'];
			}
		}
		//check if username set in cookie
		$user_data = $this->_fetchSecureCookie('AA_user_data');
		//return false if not set
		if($user_data == false)
			return false;
		//split user data into pieces
		$user_data_pieces = explode('|',$user_data);
		$user_id = $user_data_pieces[1];
		
		//set in session if required
		if( USE_SESSION_FOR_BROWSER_USER_DATA ){
			$_SESSION['AA_user_id'] = $user_id;
		}
		
		if($user_id !== false){
			return $user_id;
		}else{
			return false;
		}
	}
	
	//get the permission level of the current logged in user
	public function getCurrentUserPermissionLevelBrowser(){
		//check if set to use session
		if( USE_SESSION_FOR_BROWSER_USER_DATA ){
			//return if set in session
			if(isset($_SESSION['AA_user_permission_level'])){
				return $_SESSION['AA_user_permission_level'];
			}
		}
		//check if username set in cookie
		$user_data = $this->_fetchSecureCookie('AA_user_data');
		//return false if not set
		if($user_data == false)
			return false;
		//split user data into pieces
		$user_data_pieces = explode('|',$user_data);
		$user_permission_level = $user_data_pieces[2];
		
		//set in session if required
		if( USE_SESSION_FOR_BROWSER_USER_DATA ){
			$_SESSION['AA_user_permission_level'] = $user_permission_level;
		}
		if($user_permission_level !== false){
			return $user_permission_level;
		}else{
			return false;
		}
	}
	
	//authenticate a user and password
	public function authenticateUser($user_name,$plaintext_password){
		//get this user id from user object
		$this_user_id = $this->getUserID($user_name);
		
		//check to make sure this user exists
		if($this_user_id == null){
			$this->_setError("authenticate_user_username_error",  "Username doesn't exist.");
			return false;
		}
		
		//get this user's password hash
		$this_password = Password::where('user_id',$this_user_id)->first();
		$this_password_hash = $this_password->password;
		
		//verify password hash
		if (password_verify($plaintext_password, $this_password_hash)) {
			//check if password needs a rehash
			if (password_needs_rehash($this_password_hash, PASSWORD_BCRYPT, array('cost'=>PASSWORD_HASH_COST))) {
				//time to rehash password according to options, attempt to update database
				$user_pass = Password::where('user_id',$this_user_id)->first();
				$user_pass->password = $this->_hashPassword($plaintext_password);
				if(!$user_pass->save()){
					//saving rehashed password failed, set flash warning
					$this->_setError("authenticate_user_rehash_password_error",  "Could not save user's newly rehashed password to database.");
					//return true. although password wasn't rehashed, the user was still authenticated
					return true;
				}else{
					//saved rehashed password successfully, return true
					return true;
				}
				//fallback return true. authorization passed	
				return true;
				
			}else{
				//password doesn't need rehash. user is authenticated, return true
				return true;
			}
		} else {
			$this->_setError("authenticate_user_error",  "Password didn't match account.");
			return false;
		}
	}
	
	/*  =============================================================
							BROWSER METHODS
		=============================================================
	*/
	//attempts to log in user, sets tokens in cookies if success.
	//captcha is optional, for brute force blocker protection. if the user just answered a correct captcha as required, set as true
	public function logInUserBrowser($user_name, $user_pass, $captcha = false, $throttle_settings = false){
		//attempt to log in user with credentials
		$log_in_return = $this->_logInUser($user_name, $user_pass, $captcha);
		
		//check success
		if($log_in_return == false){
			//login failed
			return false;
		}else{
			//grab return values (auth tokens) from login
			$stateful_auth_token = ' ';
			$stateless_auth_token = ' ';
			if( USE_STATEFUL_AUTH_TOKEN )
				$stateful_auth_token = $log_in_return['stateful_auth_token'];
			if( USE_STATELESS_AUTH_TOKEN )
				$stateless_auth_token = $log_in_return['stateless_auth_token'];

			//store user data (user name|user id|permission level) in cookie
			$this_user = $this->getUserObject($user_name);
			$user_id = $this_user->id;
			$user_permission = $this_user->permission_level;
			$user_data = $user_name.'|'.$user_id.'|'.$user_permission.'|'.$stateful_auth_token.'|'.$stateless_auth_token;
			$this->_setSecureCookie('AA_user_data',$user_data);
			
			//regenerate session id
			session_regenerate_id();
			
			//return true
			return true;
			
		}
	}
	
	//logs out a browser user, unsets cookies with auth tokens
	public function logOutUserBrowser($user_name){
		//make sure user can only log themself out
		if($user_name !== $this->getCurrentUserNameBrowser())
			return false;
		
		//attempt to log out user (in database)
		$log_out_return = $this->_logOutUser($user_name);
		
		//if logout successful (in database)
		if($log_out_return){
			//logged out. unset cookies for browser
			$this->_deleteSecureCookie('AA_user_data');
			$this->_unsetSessionUserData();
			return true;
		}else{
			//failed, return false
			return false;
		}
	}
	//general method to check if user is authorized (logged in) via browser
	public function authenticate(){
		//check if userinfo set
		if(!isset($_COOKIE['AA_user_data'])){
			$this->_unsetSessionUserData();
			return false;
		}
		
		//vars to hold tokens
		$stateful_auth_token = '';
		$stateless_auth_token = '';
		$user_name = $this->getCurrentUserNameBrowser();
		
		//check stateful token if necessary
		if(USE_STATEFUL_AUTH_TOKEN){
			$stateful_auth_token = $this->_getCurrentUserStatefulAuthToken();
		}
		
		//check stateless token if necessary
		if(USE_STATELESS_AUTH_TOKEN){
			$stateless_auth_token = $this->_getCurrentUserStatelessAuthToken();
		}
		
		//authenticate tokens
		if(!$this->authenticateTokens($user_name, $stateful_auth_token, $stateless_auth_token)){
			//token(s) didn't authenticate, return false
			//$this->_unsetSessionUserData();
			return false;
		}
		
		//return true, user is authenticated
		return true;
	}
	private function _unsetSessionUserData(){
		//unsets all session data related to AlpineAuth
		
		unset($_SESSION['AA_user_name']);
		unset($_SESSION['AA_user_id']);
		unset($_SESSION['AA_user_permission_level']);
		unset($_SESSION['AA_stateless_auth_token']);
		unset($_SESSION['AA_stateful_auth_token']);
		
	}
	//modfiy a user via browser.  makes sure the user can only modify themself by ensuring user name provided matches current logged in user's username. optional parameter $admin_mode, enables a user to modfy other users' information
	public function modifyUserBrowser($user_name, $new_info_array, $admin_mode = false ){
		//make sure user can only modify themself if not in admin mode
		if($user_name !== $this->getCurrentUserNameBrowser() && !$admin_mode){
			$this->_setError("modify_user_browser_error",  "Users can only modify their own information.");
			return false;
		}
		if($this->_modifyUser($user_name, $new_info_array)){
			return true;
		}else{
			return false;
		}
	}
	//register a new user via browser
	public function registerNewUserBrowser($user_name, $password, $email = null){
		if($this->_registerNewUser($user_name, $password, $email)){
			return true;
		}else{
			return false;
		}
	}
	//remove a user via browser
	public function removeUserBrowser($user_name, $password){
		if($this->_removeUser($user_name, $password)){
			return true;
		}else{
			return false;
		}
	}
	//set a user's permission level via browser
	public function setUserPermissionLevelBrowser($user_name, $permission_level, $admin_mode = false){
		//make sure user can only modify themself if not in admin mode
		if($user_name !== $this->getCurrentUserNameBrowser() && !$admin_mode){
			$this->_setError("set_user_permission_level_admin_error",  "Users can only modify their own information.");
			return false;
		}
		//attempt to set permission level
		if(!$this->_setUserPermissionLevel($user_name, $permission_level)){
			return false;
		}
		//update permission data in session if just changed the current logged in user
		if($user_name == $this->getCurrentUserNameBrowser()){
			if( USE_SESSION_FOR_BROWSER_USER_DATA ){
				$_SESSION['AA_user_permission_level'] = $permission_level;
			}
		}
		//update cookie data
		//store user data (user name|user id|permission level) in cookie
		$this_user = $this->getUserObject($user_name);
		$user_id = $this_user->id;
		$user_permission = $this_user->permission_level;
		$stateful_auth_token = $this->_getCurrentUserStatefulAuthToken();
		$stateless_auth_token = $this->_getCurrentUserStatelessAuthToken();
		$user_data = $user_name.'|'.$user_id.'|'.$user_permission.'|'.$stateful_auth_token.'|'.$stateless_auth_token;
		$this->_setSecureCookie('AA_user_data',$user_data);
		
		//success, return true
		return true;
	}
	/*  =============================================================
							REMOTE METHODS
		=============================================================
	*/
	//builds a JSON response for a remote method
	private function _buildRemoteResponse($action,$success,$info_array = null,$errors = null){
		$this->request_mode = 'remote';
		
		//create return array and add success status
		$return_array = [
			"action" => $action,
			"success" => $success
		];
		//iterate over info array and add each to return array
		if($info_array !== null){
			foreach($info_array as $info_key=>$info_value){
				$return_array[$info_key] = $info_value;
			}	
		}
		//if errors included, add it to array
		if($errors !== null){
			$return_array["errors"] = $errors;
		}
		//create json, avoiding escaped characters
		$json = json_encode($return_array,JSON_UNESCAPED_SLASHES);
		
		//echo json response
		return $json;
	}
	//authenticate a remote user's AA_user_data for a remote request
	public function authenticateRemoteUser($user_name, $secure_user_data){
		//get instance of secure cookie storage to decrypt user data
		$storage = $this->_getSecureCookieStorage();		
		//decrypt secure user data
		$user_data = $storage->decryptRaw('AA_user_data',$secure_user_data);
		//split user data into pieces
		$user_data_pieces = $this->_splitUserData($user_data);
		
		//verify username matches decrypted data
		if($user_data_pieces['user_name'] !== $user_name){
			$this->_setError("authenticate_remote_user_name_error", "User name doesn't match secure user data.");
			return false;
		}
		//authenticate tokens
		if(!$this->authenticateTokens($user_name, $user_data_pieces['stateful_auth_token'], $user_data_pieces['stateless_auth_token'])){
			return false;
		}
		
		//authentication passed, return true
		return true;
	}
	//log in remote user
	public function logInUserRemote($user_name, $plaintext_password, $throttle_settings = null){
		$this->request_mode = 'remote';
		//attempt to log in user with credentials
		$log_in_return = $this->_logInUser($user_name, $plaintext_password, false, $throttle_settings);
		
		//the action included in the response
		$response_action = 'login';
		
		//check success
		if($log_in_return == false){
			//login failed
			$errors = $this->getErrors();
			return $this->_buildRemoteResponse($response_action,false, null,$errors);	//parameters - action, success, info array, errors
		}else{
			//grab return values (auth tokens) from login
			$stateful_auth_token_raw  = ' ';
			$stateless_auth_token_raw = ' ';
			if( USE_STATEFUL_AUTH_TOKEN )
				$stateful_auth_token_raw = $log_in_return['stateful_auth_token'];
			if( USE_STATELESS_AUTH_TOKEN )
				$stateless_auth_token_raw = $log_in_return['stateless_auth_token'];
			
			//get instance of secure cookie storage to protect tokens
			$storage = $this->_getSecureCookieStorage();
			
			//build user data (user name|user id|permission level) for secure cookie
			$this_user = $this->getUserObject($user_name);
			$user_id = $this_user->id;
			$user_permission = $this_user->permission_level;
			$user_data = $user_name.'|'.$user_id.'|'.$user_permission.'|'.$stateful_auth_token_raw.'|'.$stateless_auth_token_raw;
			
			//convert tokens and user data to HMAC protected and encrypted values, to ensure they're tamper-proof
			$secure_user_data = $storage->encryptRaw('AA_user_data',$user_data);
			
			//build the response array 
			$response_array = array();
			$response_array['user_name'] = $user_name;
			$response_array['user_permission'] = $user_permission;
			$response_array['AA_user_data'] = $secure_user_data;
			
			//grab any errors
			$errors = $this->getErrors();
			
			//build response
			return $this->_buildRemoteResponse($response_action,true, $response_array, $errors);	//parameters - action, success, info array, errors
			
		}
	}
	//attempt to log out remote user and return response
	public function logOutUserRemote($user_name, $secure_user_data){
		//define action for response
		$response_action = 'logout';
		$this->request_mode = 'remote';
		//setup response array
		$response_array = array();
		$response_array['user_name'] = $user_name;
		
		//first authenticate user
		if(!$this->authenticateRemoteUser($user_name, $secure_user_data)){
			$errors = $this->getErrors();
			//build response
			return $this->_buildRemoteResponse($response_action,false, $response_array, $errors);	//parameters - action, success, info array, errors
		}
		
		//get instance of secure cookie storage to decrypt user data
		$storage = $this->_getSecureCookieStorage();
		
		//decrypt secure user data
		$user_data = $storage->decryptRaw('AA_user_data',$secure_user_data);
		
		//check if user data decrpyted successfully
		if($user_data == false){
			// failed to decrypt secure cookie value, check $storage->errors
			$errorsString = '';
			//build string of each error
			foreach($storage->errors as $error){
				$errorsString .= $error .' ';
			}
			//throw flash message error
			$this->_setError("log_out_user_remote_decrypt_secure_user_data_error",  "Failed to decrypt secure user data. Error(s):".$errorsString );

			//grab errors, including the error just flashed
			$errors = $this->getErrors();
			
			//build response
			return $this->_buildRemoteResponse($response_action,false, $response_array, $errors);	//parameters - action, success, info array, errors
		}
		
		$user_data_pieces = $this->_splitUserData($user_data);
		
		//make sure user can only log themself out by comparing request name to name of decrypted secure user data
		if($user_name !== $user_data_pieces['user_name']){
			//throw flash message error
			$this->_setError("log_out_user_remote_user_match_error",  "Users may only log themself out. User name doesn't match secure user data.");
			//grab errors
			$errors = $this->getErrors();
			
			//build response
			return $this->_buildRemoteResponse($response_action,false, $response_array, $errors);	//parameters - action, success, info array, errors
		}
		//attempt to log out user (in database)
		$log_out_return = $this->_logOutUser($user_name);
		
		//if logout successful (in database)
		if($log_out_return){
			$errors = $this->getErrors();
			
			//build success response
			return $this->_buildRemoteResponse($response_action,true, $response_array, $errors);	//parameters - action, success, info array, errors
		}else{
			$errors = $this->getErrors();
			
			//build failure response
			return $this->_buildRemoteResponse($response_action,false, $response_array, $errors);	//parameters - action, success, info array, errors
		}
	}
	//register a new user over remote
	public function registerNewUserRemote($user_name, $password, $email = null){
		$this->request_mode = 'remote';
		//define action for response
		$response_action = 'register_new_user';
		//setup response array
		$response_array = array();
		$response_array['user_name'] = $user_name;
		
		//register new user. email is optional, depending on config setting REQUIRE_EMAIL_ACTIVATION
		if(!$this->_registerNewUser($user_name, $password, $email)){
			//failed to register new user. grab errors
			$errors = $this->getErrors();
			
			//build response
			return $this->_buildRemoteResponse($response_action, false, $response_array, $errors);	//parameters - action, success, info array, errors
		}else{
			//sucess. grab any errors just in case
			$errors = $this->getErrors();
			
			//build response
			return $this->_buildRemoteResponse($response_action, true, $response_array, $errors);	//parameters - action, success, info array, errors
		}
	}
	//modify a remote user
	public function modifyUserRemote($user_name, $new_info_array, $secure_user_data){
		$this->request_mode = 'remote';
		$response_action = 'modify_user';
		//setup response array
		$response_array = array();
		$response_array['user_name'] = $user_name;
		
		//first authenticate user
		if(!$this->authenticateRemoteUser($user_name, $secure_user_data)){
			$errors = $this->getErrors();
			//build response
			return $this->_buildRemoteResponse($response_action,false, $response_array, $errors);	//parameters - action, success, info array, errors
		}
		
		//get instance of secure cookie storage to decrypt user data
		$storage = $this->_getSecureCookieStorage();
		//decrypt secure user data
		$user_data = $storage->decryptRaw('AA_user_data',$secure_user_data);
		
		//check if user data decrpyted successfully
		if($user_data == false){
			// failed to decrypt secure cookie value, check $storage->errors
			$errorsString = '';
			//build string of each error
			foreach($storage->errors as $error){
				$errorsString .= $error .' ';
			}
			//throw flash message error
			$this->_setError("modify_user_remote_decrypt_secure_user_data_error",  "Failed to decrypt secure user data. Error(s):".$errorsString);
			
			//grab errors, including the error just flashed
			$errors = $this->getErrors();
			
			//build response
			return $this->_buildRemoteResponse($response_action,false, $response_array, $errors);	//parameters - action, success, info array, errors
		}
		
		$user_data_pieces = $this->_splitUserData($user_data);
		
		//make sure user can only modify themself (if not in admin mode) out by comparing request username to username of decrypted user data
		if($user_name !== $user_data_pieces['user_name']){
			//throw flash message error
			$this->_setError("modify_user_user_remote_user_match_error",  "Users may only modify themself. User name doesn't match secure user data.");
			//grab errors
			$errors = $this->getErrors();
			
			//build response
			return $this->_buildRemoteResponse($response_action,false, $response_array, $errors);	//parameters - action, success, info array, errors
		}
		
		//attempt to modify user
		if(!$this->_modifyUser($user_name, $new_info_array)){
			//fail
			$errors = $this->getErrors();
			return $this->_buildRemoteResponse($response_action, false, $response_array, $errors);	//parameters - action, success, info array, errors
		}else{
			//success, build response
			$errors = $this->getErrors();
			return $this->_buildRemoteResponse($response_action, true, $response_array, $errors);	//parameters - action, success, info array, errors
		}
	}
	//set a user permission level via remote
	public function setUserPermissionLevelRemote($user_name, $permission_level, $secure_user_data){
		//setup response param
		$this->request_mode = 'remote';
		$response_action = 'set_user_permission_level';
		//setup response array
		$response_array = array();
		$response_array['user_name'] = $user_name;
		
		//first authenticate user
		if(!$this->authenticateRemoteUser($user_name, $secure_user_data)){
			$errors = $this->getErrors();
			//build response
			return $this->_buildRemoteResponse($response_action,false, $response_array, $errors);	//parameters - action, success, info array, errors
		}
		
		//get instance of secure cookie storage to decrypt user data
		$storage = $this->_getSecureCookieStorage();
		//decrypt secure user data
		$user_data = $storage->decryptRaw('AA_user_data',$secure_user_data);
		
		//check if user data decrpyted successfully
		if($user_data == false){
			// failed to decrypt secure cookie value, check $storage->errors
			$errorsString = '';
			//build string of each error
			foreach($storage->errors as $error){
				$errorsString .= $error .' ';
			}
			//throw flash message error
			$this->_setError("set_user_permission_level_remote_decrypt_secure_user_data_error",  "Failed to decrypt secure user data. Error(s):".$errorsString);
			
			//grab errors, including the error just flashed
			$errors = $this->getErrors();
			
			//build response
			return $this->_buildRemoteResponse($response_action,false, $response_array, $errors);	//parameters - action, success, info array, errors
		}
		
		$user_data_pieces = $this->_splitUserData($user_data);
		
		//make sure user can only modify themself  by comparing request username to username of decrypted user data
		if($user_name !== $user_data_pieces['user_name']){
			//throw flash message error
			$this->_setError("set_user_permission_level_user_remote_user_match_error",  "Users may only modify themself. User name doesn't match secure user data.");
			//grab errors
			$errors = $this->getErrors();
			
			//build response
			return $this->_buildRemoteResponse($response_action,false, $response_array, $errors);	//parameters - action, success, info array, errors
		}
		
		
		//attempt to set permission level
		if(!$this->_setUserPermissionLevel($user_name, $permission_level)){
			$errors = $this->getErrors();
			//build response
			return $this->_buildRemoteResponse($response_action,false, $response_array, $errors);	//parameters - action, success, info array, errors
		}
		//success, return true
		$errors = $this->getErrors();
		return $this->_buildRemoteResponse($response_action,true, $response_array, $errors);	//parameters - action, success, info array, errors

	}
	/*  =============================================================
							PASSWORD RESET METHODS
		=============================================================
	*/
	//generate a user password reset token
	private function _generateUserPasswordResetToken($user_name){
		//first verify user name exists
		if(!$this->verifyUser($user_name))
			return false;
			
		//get this user's id
		$this_user_id = $this->getUserID($user_name);
		
		//create instance of randomValue class
		$randomValue = new RandomValue;
		//generate random string
		$random = $randomValue->randomKey(20);
		
		//create new token by hashing username + random
		$new_token = hash('sha512',$user_name.$random);
		
		//store token in database
		$password_reset_token = new PasswordResetToken;
		$password_reset_token->token = $new_token;
		$password_reset_token->user_id = $this_user_id;
		
		//try to save new token
		if(!$password_reset_token->save()){
			//failed to save token, set flash error return false
			$this->_setError("generate_password_reset_token_save_error",  "Could not save new password reset token to database.");
			return false;
		}else{
			//token saved successfully, return token
			return $new_token;
		}
	}
	//send a password reset email to a user
	public function sendUserPasswordResetEmail($user_name){
		//calls generateUserPasswordResetToken
		$password_reset_token = $this->_generateUserPasswordResetToken($user_name);
		
		//get the user's email to send to
		$this_user_email = $this->getUserEmail($user_name);
		if($this_user_email == false){
			$this->_setError("send_user_password_reset_email_address_error",  "Couldn't find user's email.");
			return false;
		}
		//build mail body from template
		$mail_template = file_get_contents( __DIR__.'/emails/passwordReset.html');
		$placeholders = array("[[user_name]]","[[redirect]]", "[[token]]","[[service_name]]");
		$real_values   = array($user_name, PASSWORD_RESET_REDIRECT, $password_reset_token, EM_SERVICE_NAME);
		$mail_composed = str_replace($placeholders, $real_values, $mail_template);

		//build parameters for email
		$sender_email = EM_SENDER_ADDRESS;
		$sender_name = EM_SERVICE_NAME;
		$recipient_email = $this_user_email;
		$recipient_name = $user_name;
		$subject = 'AlpineAuth Password Reset';
		$content = $mail_composed;
		
		if($this->sendMail($sender_email,$sender_name,$recipient_email,$recipient_name,$subject,$content) == true){
			return true;
		}else{
			return false;
		}
	}
	//authenticate a password reset token
	public function authenticateUserPasswordResetToken($user_name, $token){
		//verify username first
		if(!$this->verifyUser($user_name))
			return false;
		
		//get this user's ID
		$this_user_id = $this->getUserID($user_name);
		
		//get latest password reset token from database
		$password_reset_token = PasswordResetToken::where('user_id',$this_user_id)->orderBy('created_at', 'desc')->first();
		//get token creation time
		$password_reset_token_created_at = $password_reset_token->created_at;
		
		if($password_reset_token->id == null){
			//token doesn't exist, set flash error
			$this->_setError("authenticate_user_password_reset_token_exist_error",  "Password reset token doesn't exist.");
			return false;
		}
		
		//check if token matches user's user id
		if($password_reset_token->user_id !== $this_user_id){
			//user id doesn't match user provided, set flash error
			$this->_setError("authenticate_user_password_reset_token_userid_error",  "Password reset token doesn't match user provided.");
			return false;
		}
		//check if token value matches database
		if($password_reset_token->token !== $token){
			//token doesn't match, set flash error
			$this->_setError("authenticate_user_password_reset_token_token_error",  "Password reset token value incorrect.");
			return false;
		}
		
		//check if token is expired, using lifetime value from PasswordResetToken model
		//get time for now and token last update
		$token_time = strtotime($password_reset_token_created_at); 
		$now = time();
		
		//calculate time difference between now and token creation time
		$time_difference = $now - $token_time;
		$minute_difference = $time_difference / 60;
		
		//get password reset token lifetime
		$auth_token_lifetime = PasswordResetToken::getLifetimeInMinutes();
		
		//check if token is expired yet
		if($minute_difference > $auth_token_lifetime){
			//set flash warning to "token is expired"
			$this->_setError("authenticate_user_password_reset_token_expired_error",  "Password reset token is expired.");
			return false;
		}
		
		//token is valid
		return true;
	}
	//change a user's password
	public function resetUserPassword($user_name, $old_password, $password_reset_token, $new_password){
		//authenticate password reset token
		if(!$this->authenticateUserPasswordResetToken($user_name, $password_reset_token))
			return false;
		
		//grab reset token and make sure it hasn't been used yet
		$password_reset_token = PasswordResetToken::where('token',$password_reset_token)->first();
		if($password_reset_token->activated == true)
		{
			//token has already been used
			$this->_setError("reset_user_password_token_activated_error",  "Password reset token has already been used.");
			return false;
		}
		
		//authenticate username and password
		if(!$this->authenticateUser($user_name, $old_password))
			return false;
		
		//get user id
		$this_user_id = $this->getUserID($user_name);
		
		//updates database with hashed newPassword
		$user_pass = Password::where("user_id",$this_user_id)->first();
		$user_pass->password = $this->_hashPassword($new_password);
		$user_pass->number = $user_pass->number + 1;
		$user_pass->last_reset = date('Y-m-d H:i:s');
		if(!$user_pass->save()){
			//saving new password failed, set flash warning
			$this->_setError("reset_user_password_save_error",  "Could not save user's new password to database.");
			return false;
		}else{
			//get latest password reset token from database to 
			//update activated status, signalling token has been used
			$password_reset_token->activated = true;
			if(!$password_reset_token->save()){
				//flash error, couldn't update password reset token activated status
				$this->_setError("reset_user_password_update_activated_error",  "Could not update password reset token's 'activated' column in database.");
				return false;
			}
			
			return true;
		}

	}
	
	//hash a password. second optional paremeter is cost, defaults to PASSWORD_HASH_COST constant if not set
	private function _hashPassword($password, $cost = PASSWORD_HASH_COST){
		//hash password
		$hashed_password = password_hash($password, PASSWORD_BCRYPT, array ('cost'=>$cost));
		//return hash
		return $hashed_password;
	}
	
	/*=================================================================	
						STATEFUL AUTH TOKEN METHODS 
						(tokens stored in database)
	===================================================================
	*/
	//generate a stateful auth token. this is stored serverside in a database
	private function _generateStatefulAuthToken($user_name,$user_id,$user_password_hash){
		//build credentials string for token
		$new_token_credentials = time().$user_name."..".$user_id."..".$user_password_hash."..".date("Y-m-d H:i:s");
		
		//create token from credentials
		$new_token = $this->_hashPassword($new_token_credentials, 5);
		
		//return the token, or null if didn't work
		if($new_token !== false){
			return $new_token;
		}else{
			return null;
		}
	}
	//authenticate a stateful auth token
	private function _authenticateStatefulAuthToken($user_name, $token){
		//get this user's user ID
		$this_user_id = $this->getUserID($user_name);
		
		//if user id not found, return false with error message
		if($this_user_id == null){
			$this->_setError("authenticate_user_by_stateful_token_user_exist_error",  "User doesn't exist.");
			return false;
		}
		
		//get this auth token from database
		$this_auth_token = AuthToken::where('token',$token)->first();
		if($this_auth_token->user_id == null){
			//auth token doesn't exist
			$this->_setError("authenticate_user_by_stateful_token_token_exist_error",  "Auth Token (".$token.") doesn't exist.");
		}
		//get user id associated with auth token
		$this_auth_token_user_id = $this_auth_token->user_id;
		
		//check if this user's id matches the token's user_id
		if(!$this_user_id == $this_auth_token_user_id){
			//user id's do'nt match
			$this->_setError("authenticate_user_by_stateful_token_error",  "Stateful auth token doesn't match user.");
			return false;
		}
		
		//get this token's info from database
		$this_token_user_id = $this_auth_token->user_id;
		$this_token_created_at = $this_auth_token->created_at;
		$this_token_updated_at = $this_auth_token->updated_at;
		
		//get time for now and token last update
		$token_time = strtotime($this_token_created_at); 
		$now = time();
		
		//calculate time difference between now and token last update time
		$time_difference = $now - $token_time;
		$minute_difference = $time_difference / 60;
		
		//get stateful auth token lifetime
		$auth_token_lifetime = AuthToken::getLifetimeInMinutes();
		
		/*		debug echos
		echo "this token: ".$token."<br>";
		echo "this token length: ".count($this_token)."<br>";
		echo "token time: ".$token_time."<br>";
		echo "now time: ".$now."<br>";
		echo "minute difference: ".$minute_difference."<br>";
		echo "auth_token_lifetime: ".$auth_token_lifetime."<br>";
		*/
		
		//check if token is expired yet
		if($minute_difference > $auth_token_lifetime){
			//set flash warning to "token is expired"
			$this->_setError("authenticate_token_expired_error",  "User's session has expired.");
			return false;
		}else{
			//token valid and not expired
			return true;
		}
	}
	/*=================================================================	
						STATELESS AUTH TOKEN METHODS  
						(tokens not stored in database)
	===================================================================
	*/
	//stateless token methods derived from work by Joseph Scott, https://josephscott.org/archives/2013/08/better-stateless-csrf-tokens/ 
	//generate a new stateless auth token
	private function _generateStatelessAuthToken( $user_name, $timeout = 31536000   ) {
		//note: timeout is in seconds. default is one year
		$now = microtime( true );
		$randomValue = new RandomValue;
		$randomLength = $randomValue->randomNumberBetween(15,30);
		$random = $randomValue->randomKey($randomLength);
		
		$user_password_number = $this->getUserPasswordNumber($this->getUserID($user_name));
		$data_str = $user_name.".".$user_password_number.".".STATELESS_AUTH_TOKEN_SECRET;
		
		//generate the token, including the creation time and timeout values in the token
		$hash = hash_hmac( 'sha256', "$data_str-$now-$timeout-$random", STATELESS_AUTH_TOKEN_KEY );
		
		//token contains four values separated by dashes "-". hash, now timestamp, timeout,and a random value
		return "$hash-$now-$timeout-$random";
	}
	//verify a stateless auth token
	private function _authenticateStatelessAuthToken( $user_name, $token ) {
		//extract each section from the token
		list( $hash, $hash_time, $timeout, $random ) = explode( '-', $token, 4 );
		if ( 
			empty( $hash )
			|| empty( $hash_time )
			|| empty( $timeout )
			|| empty( $random )
		) {
			$this->_setError("verify_stateless_token_field_error",  "Missing field from stateless auth token ($token) for username ($user_name).");
			return false;
		}
	 
		if ( microtime( true ) > $hash_time + $timeout ) {
			$this->_setError("verify_stateless_token_expired_error",  "Stateless auth token has expired.");
			return false;
		}
		//get user password number
		$user_password_number = $this->getUserPasswordNumber($this->getUserID($user_name));
		
		//build data string with server's secret
		$data_str = $user_name.".".$user_password_number.".".STATELESS_AUTH_TOKEN_SECRET;
		
		//create string to check against
		$check_string = "$data_str-$hash_time-$timeout-$random";
		
		//create hash to check against
		$check_hash = hash_hmac( 'sha256', $check_string, STATELESS_AUTH_TOKEN_KEY );
		
		//check if created hash matches the challenge token, proving validity
		if ( $check_hash === $hash ) {
			return true;
		}
		//throw flash error
		$this->_setError("verify_stateless_token_hash_error",  "Stateless auth token hash didn't match server's outcome. Token appears to be invalid.");
		return false;
	}
	
	/*=================================================================	
								MAIL METHODS
							(using PHPMailer)
	===================================================================
	*/
	//send an email
	public function sendMail($sender_email,$sender_name,$recipient_email,$recipient_name,$subject,$content){
		//load PHPMailer
		require_once( __DIR__.'/helpers/PHPMailer/PHPMailerAutoload.php' );
		
		//create instance of mailer
		$mail = new PHPMailer(true);
		
		//build mail
		$mail->IsHTML(true);
		try{
			$mail->AddAddress($recipient_email, $recipient_name);
			$mail->SetFrom($sender_email, $sender_name);
		} catch(phpmailerException $e){
			//catch PHPMailer exception
			$this->_setError("send_mail_address_error",  "PHPMailer couldn't add email address. Error: ".$e->errorMessage() );
			return false;
		}
		
		$mail->Subject = $subject;
		//build and add html body content
		$mail->Body = $content;
		//build and add non-html body content
		$mail->AltBody = $content;
		
		//attempt to send mail
		try{
			$mail->Send();
			return true;
		} catch(phpmailerException $e){
			//catch PHPMailer exception
			$this->_setError("send_mail_error",  "PHPMailer couldn't send email. Error: ".$e->errorMessage() );
			return false;
		}

	}
	
	/*=================================================================	
							SECURE STORAGE METHODS
						(using MrClay_CookieStorage)
	===================================================================
	*/
	//set an encrypted and signed cookie
	private function _setSecureCookie($name,$value){
		//get instance of secure cookie storage
		$storage = $this->_getSecureCookieStorage();
		
		//try to save secure cookie
		if ($storage->store($name, $value)) {
			// secure cookie stored successfully. cookie OK length and no complaints from setcookie()
			return true;
		} else {
			// failed to store secure cookie, check $storage->errors
			$errorsString = '';
			//build string of each error
			foreach($storage->errors as $error){
				$errorsString .= $error .' ';
			}
			//set flash message with any errors returned
			$this->_setError("set_secure_cookie_save_error",  "Failed to store secure cookie. Errors: ".$errorsString);
			return false;
		}
	}
	//fetch an encrypted and signed cookie
	private function _fetchSecureCookie($name){
		//get instance of secure cookie storage
		$storage = $this->_getSecureCookieStorage();
		
		//fetch cookie value
		 $cookie = $storage->fetch($name);
		 if (is_string($cookie)) {
			// valid cookie
			$age_in_seconds = time() - $storage->getTimestamp($name);
			//return 'age: '.$age.'  cookie: '.$cookie;
			return $cookie;
		 } else {
			 if (false === $cookie) {
				 //data was altered!
				 $this->_setError("fetch_secure_cookie_altered_error",  "Secure cookie appears to be tampered with. ".$storage->errors[0]);
				 return false;
			 } else {
				//cookie not present
				$this->_setError("fetch_secure_cookie_exists_error",  "Secure cookie does not exist.");
				return false;
			 }
		 }
	}
	
	//remove a secure cookie
	private function _deleteSecureCookie($name){
		//get instance of secure cookie storage
		$storage = $this->_getSecureCookieStorage();
		
		$storage->delete($name);
		
		return true;
	}
	
	//get a secure cookie storage instance, for use in all secure cookie storage methods
	private function _getSecureCookieStorage(){
		//get current time
		$now = time();
		$expiration_time = $now + COOKIE_LIFETIME_IN_SECONDS;
		

		//setup encrypted and signed cookie options
		$storage = new MrClay_CookieStorage(array(
			'secret' => ENCRYPTED_COOKIE_STORAGE_SECRET,
			'domain' => COOKIE_DOMAIN,
			//'secure' => true,
			'path' => COOKIE_PATH,
			'expire' => $expiration_time,
			'mode' => MrClay_CookieStorage::MODE_ENCRYPT
		));
		
		//return new storage object
		return $storage;
	}
	//get a secure email storage instance, for use for encrypting/decrypting user email addresses
	private function _getSecureEmailStorage(){
		//get current time
		$now = time();
		$expiration_time = $now + 10000000000000000000000000000000000000;
		
		//setup encrypted and signed cookie options
		$storage = new MrClay_CookieStorage(array(
			'secret' => ENCRYPTED_EMAIL_SECRET,
			'domain' => COOKIE_DOMAIN,
			//'secure' => true,
			'path' => COOKIE_PATH,
			'expire' => $expiration_time,
			'mode' => MrClay_CookieStorage::MODE_ENCRYPT
		));
		
		//return new storage object
		return $storage;
	}
	//get a secure email storage instance, for use for encrypting/decrypting user email addresses
	private function _getSecureGeneralStorage(){
		//get current time
		$now = time();
		$expiration_time = $now + 10000000000000000000000000000000000000;
		
		//setup encrypted and signed cookie options
		$storage = new MrClay_CookieStorage(array(
			'secret' => GENERAL_ENCRYPTION_SECRET,
			'domain' => COOKIE_DOMAIN,
			//'secure' => true,
			'path' => COOKIE_PATH,
			'expire' => $expiration_time,
			'mode' => MrClay_CookieStorage::MODE_ENCRYPT
		));
		
		//return new storage object
		return $storage;
	}
	/*=================================================================	
						FORM SPAM PREVENTION METHODS
	===================================================================
	*/
	//prevent form spam by creating a secret hidden form field
	public function preventFormSpam($name){
		//generate anti spam key
		$anti_form_spam_key = substr(hash('sha256',$name.microtime()), 0, 15);
		//flash the key in the session for grabbing after request
		$_SESSION['anti_form_spam_key:'.$name] = $anti_form_spam_key;
		//flash referer in session to compare against 
		$_SESSION['anti_form_spam_referer:'.$name] = $this->getCurrentURL();
		
		//return hidden input
		return '<input type="text" name="'.$anti_form_spam_key.'" style="display:none" value="" />';
	}
	//check for form spam by seeing if hidden form field was filled. returns true if spam bot suspected
	public function checkFormSpam($request_type,$name){
		//grab form name from session 
		if(!isset($_SESSION['anti_form_spam_key:'.$name]) || !isset($_SESSION['anti_form_spam_referer:'.$name])){
			$this->_setError("check_form_spam_set_error",  "Anti form spam key or referer not set.");
			return true;
		}
		//check if referer matches url set in session. if referer doesn't match, return true, suspected bot
		if(strpos($_SERVER['HTTP_REFERER'],$_SESSION['anti_form_spam_referer:'.$name]) === false){
			$this->_setError("check_form_spam_referer_error",  "Referer doesn't match form URL.");
			$_SESSION['err_referer'] = $_SERVER['HTTP_REFERER'];
			$_SESSION['err_strpos output'] = strpos($_SERVER['HTTP_REFERER'],$_SESSION['anti_form_spam_referer:'.$name]);
			return true;
		}
		
		$form_name = $_SESSION['anti_form_spam_key:'.$name];
		//unset session var
		unset($_SESSION['anti_form_spam_key:'.$name]);
		unset($_SESSION['anti_form_spam_referer:'.$name]);
		//force request type to lowercase
		$request_type = strtolower($request_type);
		//check request type
		if($request_type == 'post'){
			//if form is set and filled in, suspected spam bot. return true
			if ((isset ($_POST[$form_name])) && ($_POST[$form_name] != '')) {
				return true; 
			}else{
				return false;
			}
		}else if($request_type == 'get'){
			//if form is set and filled in, suspected spam bot. return true
			if ((isset ($_GET[$form_name])) && ($_GET[$form_name] != '')) {
				return true; 
			}else{
				return false;
			}
		}
	}
	/*=================================================================	
				USER ACCOUNT ACTIVATION VIA EMAIL METHODS
	===================================================================
	*/
	//activate a user's account
	public function activateUser($user_name, $activation_code){
		//get activation code from database
		$user = $this->getUserObject($user_name);
		$user_code = $user->activation_code;
		
		//authenticate activation code
		if($user_code == $activation_code){
			//code authenticated
			$user->activated = true;
			//try to save updated user
			if(!$user->save()){
				//failed save, set flash message
				$this->_setError("activate_user_save_error",  "Couldn't updated user's activated status in database.");
				return false;
			}else{
				//success
				return true;
			}
		}else{
			//activation code didn't match, set flash message
			$this->_setError("activate_user_code_error",  "Account activation code incorrect.");
			return false;
		}
	}
	//send an account confirmation email
	private function _sendUserActivationEmail($user_name, $user_email, $activation_code){
		//get the user's email to send to
		$this_user = $this->getUserObject($user_name);
		$this_user_email = '';
		//check if need to decrypt email
		if( ENCRYPT_USER_EMAIL_ADDRESSES ){
			$this_user_email = $this->_decryptEmailAddress($user_name,$this_user->email);
		}else{
			$this_user_email = $this_user->email;
		}
		//check for decryption failure
		if($this_user_email == false)
			return false;
		$this_user_activation_code = $this_user->activation_code;
		
		//build mail body from template
		$mail_template = file_get_contents( __DIR__.'/emails/accountActivation.html');
		$placeholders = array("[[user_name]]","[[redirect]]", "[[code]]","[[service_name]]");
		$real_values   = array($user_name, ACCOUNT_ACTIVATION_REDIRECT, $this_user_activation_code, EM_SERVICE_NAME);
		$mail_composed = str_replace($placeholders, $real_values, $mail_template);

		//build parameters for email
		$sender_email = EM_SENDER_ADDRESS;
		$sender_name = EM_SERVICE_NAME;
		$recipient_email = $this_user_email;
		$recipient_name = $user_name;
		$subject = EM_SERVICE_NAME.' Account Activation';
		$content = $mail_composed;
		
		if($this->sendMail($sender_email,$sender_name,$recipient_email,$recipient_name,$subject,$content) == true){
			return true;
		}else{
			return false;
		}
	
	}
	//resend an account activation email
	//send an account confirmation email
	public function resendUserActivationEmail($user_name){
		//get the user's email and activation code
		$this_user = $this->getUserObject($user_name);
		$activation_code = $this_user->activation_code;
		$this_user_email = '';
		//check if need to decrypt email
		if( ENCRYPT_USER_EMAIL_ADDRESSES ){
			$this_user_email = $this->_decryptEmailAddress($user_name,$this_user->email);
		}else{
			$this_user_email = $this_user->email;
		}
		//attempt to send activation email
		if(!$this->_sendUserActivationEmail($user_name, $this_user_email, $activation_code)){
			return false;
		}
		
		return true;
	
	}
	//register a new user. creates a new user and sends activation email if required
	private function _registerNewUser($user_name, $plaintext_password, $email = null){
		//check if email is required and included
		if(REQUIRE_EMAIL_ACTIVATION){
			if($email == null){
				//email not included, throw flash error
				$this->_setError("register_new_user_email_error",  "Account requires email for activation.");
				return false;
			}
			
			//check if email has been used already
			$users_with_email_count = User::where('email',$email)->count();
			
			if($users_with_email_count !== 0){
				//email already in use, throw flash error
				$this->_setError("register_new_user_email_used_error",  "Email is already in use.");
				return false;
			}
			
		}
		
		
		//attempt to create new user
		if(!$this->_createUser($user_name,$plaintext_password,$email))
			//failed to create user
			return false;
		
		//check if email activation required. if not, user was created successfully so return true
		if( !REQUIRE_EMAIL_ACTIVATION )
			return true;
			
		//get activation code for email
		$this_user = $this->getUserObject($user_name);
		$activation_code = $this_user->activation_code;
		
		//attempt to send account activation email
		if(!$this->_sendUserActivationEmail($user_name, $email, $activation_code))
			//failed to send user activation email
			return false;
			
		//success
		return true;
		
	}
	
	/*=================================================================	
				USER ACCOUNT PERMISSION LEVEL METHODS
	===================================================================
	*/
	//set a user's permission level
	private function _setUserPermissionLevel($user_name, $permission_level){
		//check if permission is numeric
		if(!is_numeric($permission_level)){
			//fail
			$this->_setError("set_user_permission_level_numeric_error",  "Permission level must be a number.");
			return false;
		}
		//get this user
		$this_user = $this->getUserObject($user_name);
		
		//update user permission level in database
		$this_user->permission_level = $permission_level;
		if(!$this_user->save()){
			//fail
			$this->_setError("set_user_permission_level_save_error",  "Couldn't update user's permission level in database.");
			return false;
		}else{
			//success
			return true;
		}

	}
	//get a user's permission level from the database
	public function getUserPermissionLevel($user_name){
		//get this uer
		$this_user = $this->getUserObject($user_name);
		
		//get permission level 
		$permission_level = $this_user->permission_level;
		
		//return it
		return $permission_level;
	}
	/*=================================================================	
						ENCRYPT/DECRYPT METHODS
	===================================================================
	*/
	//encrypt a raw email address and apply an HMAC
	private function _encryptEmailAddress($name,$raw){
		//get secure storage instance
		$storage = $this->_getSecureEmailStorage();
		//encrypt
		$encrypted = $storage->encryptRaw($name,$raw);
		//return 
		return $encrypted;
	}
	//decrypt an encrypted email address and verify HMAC
	private function _decryptEmailAddress($name,$encrypted){
		//get secure storage instance
		$storage = $this->_getSecureEmailStorage();
		//encrypt
		$decrypted = $storage->decryptRaw($name,$encrypted);
		//check if user data decrypted successfully
		if($decrypted == false){
			// failed to decrypt secure cookie value, check $storage->errors
			$errorsString = '';
			//build string of each error
			foreach($storage->errors as $error){
				$errorsString .= $error .' ';
			}
			//throw flash message error
			$this->_setError("decrypt_email_error",  "Failed to decrypt email address. Error(s):".$errorsString );
			return false;
		}
		//return 
		return $decrypted;
	}
	//encrypt a raw string and apply an HMAC
	public function encryptGeneral($name,$raw){
		//get secure storage instance
		$storage = $this->_getSecureGeneralStorage();
		//encrypt
		$encrypted = $storage->encryptRaw($name,$raw);
		//return 
		return $encrypted;
	}
	//decrypt an encrypted string and verify HMAC
	public function decryptGeneral($name,$encrypted){
		//get secure storage instance
		$storage = $this->_getSecureGeneralStorage();
		//encrypt
		$decrypted = $storage->decryptRaw($name,$encrypted);
		//check if user data decrpyted successfully
		if($decrypted == false){
			// failed to decrypt secure cookie value, check $storage->errors
			$errorsString = '';
			//build string of each error
			foreach($storage->errors as $error){
				$errorsString .= $error .' ';
			}
			//throw flash message error
			$this->_setError("decrypt_general_error",  "Failed to decrypt secure data. Error(s):".$errorsString );
			return false;
		}
		//return 
		return $decrypted;
	}
	
	/*=================================================================	
						BRUTE FORCE BLOCKER METHODS
	===================================================================
	*/
	//get status of brute force blocker
	public function getBruteForceBlockStatus($throttle_settings = null){
		//check failed logins if USE_BRUTE_FORCE_PREVENTION is enabled
		if( USE_BRUTE_FORCE_PREVENTION ){
			//check status of BruteForceBlock
			$BFBresponse = BruteForceBlock::getLoginStatus($throttle_settings);
			//build response array
			$response_array = array();
			$response_array['status'] = $BFBresponse['status'];
			$response_array['message'] = $BFBresponse['message'];
			
			//return response
			return $response_array;
		}else{
			//not enabled
			$this->_setError("get_login_brute_force_blocker_enabled_error",  "Brute force blocker is not enabled.");
			return false;
			
		}
	}
	//clear failed logins table in database
	public function clearBruteForceTable(){
		//try to clear
		$BFBresponse = BruteForceBlock::clearDatabase();
		//check response
		if($BFBresponse !== true){
			return $BFBresponse;
		}else{
			return true;
		}
	}
	
	/*================================================
					UTILITY
	=================================================*/
	//get current page url
	public function getCurrentURL()
	{
		$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
		$domainName = $_SERVER['HTTP_HOST'].'/';
		return $protocol.$domainName;
	}
	
	/*===============================================
					USER STATS METHODS
	================================================*/
	//get list of all user
	public function getAllUsersObjects(){
		$all_users = User::all();
		return $all_users;
	}
	
	//get list of all users in an HTML table
	public function getAllUsersTable(){
		//get all users
		$all_users = $this->getAllUsersObjects();
		//setup table string
		$table_string = '<table border="1"><thead>
		<tr><th>ID</th><th>username</th><th>logged_in</th><th>email</th><th>permission_level</th><th>activated</th><th>updated_at</th><th>created_at</th></tr></thead>';
		foreach($all_users as $user){
			$user_email = '';
			//check if need to decrypt emails
			if( ENCRYPT_USER_EMAIL_ADDRESSES ){
				$decrypted_user_email = $this->_decryptEmailAddress($user->name,$user->email);
				if($decrypted_user_email == false)
					return false;
				$user_email = $decrypted_user_email;
			}else{
				$user_email = $user->email;
			}
			$table_string .= '<tr><td>'.$user->id.'</td><td>'.$user->name.'</td><td>'.$user->logged_in.'.</td><td>'.$user_email.'</td><td>'.$user->permission_level.'</td><td>'.$user->activated.'</td><td>'.$user->updated_at.'</td><td>'.$user->created_at.'</td></tr>';
		}
		$table_string .= '</table>';
		
		return $table_string;
	}
	
	//get a user object from the database
	public function getUserObject($user_name){
		//grab this user
		$this_user = User::where('name',$user_name)->first();
		@$this_user_id = $this_user->id;		//suppress warning if non-existant
		
		//check if this user exists
		if($this_user_id !== null){
			return $this_user;
		}else{
			return false;
		}
	}
}
?>