#AlpineAuth
By Evan Francis, 2014

* [Overview](#overview)
* [Features](#features)
* [Authentication](#authentication)
* [Demos](#demos)
* [Emails](#emails)
* [Brute Force Protection](#brute-force-protection)
* [HTML Form Spam Prevention](#html-form-spam-prevention)
* [User Permission Levels](#user-permission-levels)
* [Errors and Debugging](#errors-and-debugging)
* [List of All Methods](#list-of-all-methods)
* [Configuration](#configuration)
* [Third Party Components and Credit](#third-party-components-and-credit)
* [Disclaimer](#disclaimer)

##Overview
AlpineAuth is a user authentication and management library with an emphasis on security and ease of use. The library allows you to quickly and easily add a system of users to your project and create secure pages or methods protected by user authentication. There are many user libraries out there that use outdated and insecure techniques such as system-wide password salts, hash functions or cryptographic ciphers that are no longer considered secure, ignoring brute-force attacks, and storage of unencrypted information on the client. Of the libraries that use sufficient techniques, even fewer offer a wide enough range of options to be useful in most situations. AlpineAuth aims to fix that by providing an easy to use and reliable solution. 

Methods are divided into two types, browser and remote. Browser methods are for use when building a typical web page that will be accessed by a web browser. Remote methods are for use when building an application that is accessing the server remotely, such as a mobile app or video game. Browser methods will return `true` or `false` depending on the result of the request. Remote methods will return a JSON response containing information about the request and the result. For instance, logInUserBrowser(username,password) would return `true` if the given the proper credentials. Given the same correct credentials, logInUserRemote(username,password) would return 

```
{
  "action":"login",
  "success":true,
  "user_name":"evan",
  "user_permission":0,
  "AA_user_data":"2vMcLb2s5iPiA-bnA|5-KQVmvjD1Mg7TUYeFQaczwxzco|n7ak7i|uW7gBnZ9Yn7e2rMncg43oLlokNbzdSjVYd8wx3K9sZo3Lb1mJMGgnmJuaU1+S5NijSyb8EM9FalN3JfWyb9H2F4WLfdeQX9lZR7nuo0Vzmz6+FAa63e6BLMATfgTullfP6OGCXTsKfUSdVeZpWb93vxdfPMDOER6k1wolArJaJtgNjK972TTOXS9w00KoEpJh8mJy7WlWyohNK1BB5urpEhbWyAIDaDE2E95j7b1toDtNqdTla16LWFvtCKAGAwqh",
  "errors":false
}

```
This way an app on a remote device such as a mobile phone or video game can be aware of the response and store the returned user data for later use.  

###Installation
To use AlpineAuth, move the entire AlpineAuth directory to somewhere on your web server, then include the `AlpineAuth.class.php` file and create a new instance like so:
```
require_once( __DIR__.'/AlpineAuth/AlpineAuth.class.php');

$alpineAuth = new AlpineAuth();
```
Then set your configuration settings in `AlpineAuth.config.php`. You can use the included `AlpineAuth.sql` file to build the tables required.
##Features

###security

* token-based authentication
 * stateful auth tokens (stored in a database)
 * stateless auth tokens (never stored on server) verified with an HMAC (signed and tamper-proof), that expire when a user’s password changes
* all information stored on the client, whether it be in browser cookies or on a remote device, is verified for integrity with HMAC and encrypted with mcrypt and the Rijndael 256 cipher
* passwords hashed with Bcrypt. automatically rehashed when settings are changed. salts are automatically generated for each individual password 
* optional encryption and HMAC protection of user email addresses in the database
* automatic brute force attack protection using BruteForceBlock
 * enforce a time delay between requests when a brute force attack is detected, rendering the attack useless
 * optionally require the user to solve a captcha
* PDO parameter binding for database queries via Laravel’s Illuminate Database toolkit to prevent SQL injection
* optional use of only encrypted cookies for user data storage (user name, ID, permission, auth tokens), or encrypted cookies as well as sessions when possible
* browser session IDs are regenerated after successful login
* stateful, one-time use password recovery tokens via email
* spam bot prevention for HTML forms 
  * checks input field hidden with CSS
  * verifies HTTP_REFERER
* by default, methods  modifyUserBrowser() and setUserPermissionLevelBrowser() only allow users to modify themselves unless admin_mode parameter is set to true to protect against destructive activities. The methods modifyUserRemote() and setUserPermissionLevelRemote() only allow the user to modify themself no matter what, to avoid malicious destructive activities.
  
###user management
* register new users
* modify a user's information
* retrieve a user's information
* remove users and all associated data
* optionally require account activation via email
* optionally expire user passwords after a set time limit, require reset via email
* send users emails automatically when required, built from customizable HTML files 
 * account activation email sent immediately after a user registers for a new account
 * password reset email sent with sendUserPasswordResetEmail(username)  
* set and get user permission levels (a numeric value)
* verify a user exists
* automatically generate an html table of all users

##Authentication
To use AlpineAuth properly you should understand how it works. Authentication is done with tokens, a user provides a cookie containing a token with each request and AlpineAuth determines whether or not the token is valid. If it is, you know the user is logged in and legitimate. When a user successfully logs in, they are given a cookie that looks similar to 
`e1c0FRonUbAMmcHg|YgyIDAeeaOOP9qjFWMINe5nfg|f1ab4n|XtsqgiiLDypY0MdK6SgifPs4CFVS`
`fjbdKnvfzXPW+6glqzMsgviMMfg87mr1brpwDSi0P415xj7VTgoOwiKfGzz+U0WGW0epwU+/nNvWGhv`
`qjZpVQhrxGE+AMS+rN1OiiyDliOlAJOnRSunXcZ3W+ep6tkfY8iO2xkMVu/qApnhp2afLvrswqRxoaqK`
`vHWtUYL4Z2F2iY8He1aLAogRAmSC1iAY08rChXSA4nn5TJsidUxCATArHL/cHS0O21nxT6`.

This cookie contains the user’s *username*, *user ID*, *permission level*, and any *tokens* required. The cookie is encrypted with the Rijandael 256 cipher and verified as tamper-proof with an HMAC (Hash-based Message Authentication Code).
Both browser and remote authentication are done by providing AlpineAuth with this cookie, at which point the library can decrypt and authenticate the data contained within. 

**The main difference between browser and remote methods** is that with browser methods, when the user logs in the cookie is saved automatically in a browser cookie, so any requests after that automatically grab the values from the browser cookie array to authenticate. When a user logs in with a remote method the cookie is returned in the JSON response, so the remote device must store this cookie and supply it with each following request to prove that users authenticity. 


##Demos
There are three demos included in the repository; a browser demo, a remote demo and an encryption demo. It is recommended to read over these demo pages to get comfortable with how everything works. Remember that these demos are not complete, they don't do any input filtering or validation.


The **browser demo** contains the following pages:

* ‘login.php’ - provides the user with forms to test the following methods
 * logInUserBrowser() 
 * registerNewUserBrowser()
 * removeUserBrowser()
 * sendUserPasswordResetEmail()
 * preventFormSpam() and checkFormSpam()
* ‘protected.php’ - an example of a protected page, sends the user to ‘login.php’ if not authenticated and authorized. provides forms to test the following methods
 * modifyUserBrowser(), protected because by default a user can only modify themself
 * setUserPermissionLevelBrowser()
 * logOutUserBrowser()
* ‘accountActivation.php’ - an example of the account activation page that is linked to in a sent email, provides form to test the following methods
 * activateUser()
* ‘passwordReset.php’ - an example of the password reset page that is linked to in a sent email. provides form to test the following methods
 * resetUserPassword()

The **remote demo** contains only a single page. It looks similar to the ‘login.php’ page of the browser demo, except when you use any of the test forms the JSON response for the remote request is displayed on the page. There are forms to test the following methods:

* 'remoteDemo.php'
 * logInUserRemote()
 * logOutUserRemote() 
 * registerNewUserRemote()
 * modifyUserRemote()
 * setUserPermissionLevelRemote()

The **encryption** demo is an example of the encryption and decryption included. It also includeds a list of randomly generated strings that can be used for your cryptographic keys and secrets in the `AlpineAuth.config.php` configuration file. 

* 'encryptDemo.php' - an example of the encryption and decryption offered. a randomly generated list of cryptographic keys/secrets is included. provides examples for the following methods
 * encryptGeneral()
 * decryptGeneral()
 

##Emails
AlpineAuth uses the PHPMailer class to send emails to users to reset their passwords or activate their accounts after registration. The emails are built from templates in the `/emails` folder. You can compose your emails in any way you see fit using basic HTML and inline CSS styles. The important information can be inserted with placeholder variables that are replaced by the real variables before sending. Please check the included HTML email files to see the correct placeholder variables. Example:
```
"accountActivation.html"

<p>Hello [[user_name]] and thank you for registering an account with [[service_name]]! </p>
<p>To activate your account and start using [[service_name]], please click the following link
	<a href='[[redirect]]?code=[[code]]&u=[[user_name]]'>CLICK</a>
</p>
```

NOTE: For testing emails locally, [Test Mail Server Tool](http://www.toolheap.com/test-mail-server-tool/) is a great option.


##Brute Force Protection
AlpineAuth uses the BruteForceBlock class to provide protection against brute force attacks that attempt to crack users' passwords. Enable it with the `USE_BRUTE_FORCE_PREVENTION` config setting. All failed logins site-wide are stored in a database, and you set a limit to how many failed logins can happen in 10 minutes. If it's greater than your minimum threshold, it's assumed a brute force attack is happening and either a timed delay between login requests is enforced or a captcha is required. The login methods both take an array of throttle settings as a parameter. If it's not set the default array is used but this should *not* be relied on. You should base these settings on the size of your user base and its activity.

Here is the default throttle settings array to show how you can build it. Note that captcha isn't supported for remote methods, so only a time delay can be used if you're using remote methods.
```php
// array of throttle settings
// # recent failed logins => response
$throttle_settings = [
	50 => 2, 			//delay in seconds
	150 => 4, 			//delay in seconds
	300 => 'captcha'	//captcha
];
```
When using the browser login method, the parameters are `logInUserBrowser(username,password,captcha=false,throttle_settings=false)`. 
If AlpineAuth returns the `login_bfb_captcha` error, the user is required solve a CAPTCHA. The `captcha` parameter should only be true if it's *required* and was just *solved correctly* by the user. Similarly, if the `login_bdb_delay` error is returned the use is required to wait a time delay before logging in again.

When using the remote login method, the parameters are 
`logInUserRemote(username, password, throttle_settings = false)`. There is no option for CAPTCHA with remote requests.

NOTE: By default BruteForceBlock clears database entries older than 20-30 minutes

##HTML Form Spam Prevention
There are two methods for preventing form spam on your webpages, preventFormSpam(name) and checkFormSpam(request_type,name). The preventFormSpam() method returns a hidden `<input>` tag and saves the page URL in a session variable. In the script that your form POSTs/GETs to, when you call checkFormSpam() it checks to see if the hidden input is empty and the HTTP_REFERER matches the session variable that was set. If neither is true, a spam bot is suspected and checkFormSpam() returns `true`.

Example usage:
```php
<form method="post" action="">
	<h2>Register New User (send email for activation)</h2>
	<label for="username">Username:</label>
	<input type="text" name="username" id="username">
	<label for="password">Password:</label>
	<input type="password" name="password" id="password">
	<label for="password">Email:</label>
	<input type="text" name="email" id="email">
	<input type="hidden" name="action" value="register">
	<?php echo $alpineAuth->preventFormSpam('registerUser'); ?>	<!-- here -->
	<input type="submit"></input>
</form>
```
Then in the script it posts to:
```php
// check for form spam
if($alpineAuth->checkFormSpam('post','registerUser')){
	//form spam bot detected!!!
	return;
}else{
	//NO form spam bot detected
}
 ```

##User Permission Levels
User permissions in AlpineAuth are handled as a basic numeric value. If all you need is a few types of users, say 'normal' 'contributor' 'admin' and 'superadmin', the built in system would be sufficient by assigning values like 1, 2, 3 and 4. If you need a more sophisticated role-based system, I suggest you use something like [PHPRBAC](http://phprbac.net/) alongside AlpineAuth. Such a system relies on only a user ID for referencing a user, so integrating it wouldn't be a problem.

##Errors and Debugging
AlpineAuth uses an internal error message system. Depending on whether you are making a remote request or a browser-based request, errors will be stored in an object’s array variable or in the $_SESSION array. Some of the error messages are a bit verbose and could be dangerous to expose to the public, for instance:
`[modify_user_remote_decrypt_secure_user_data_error]=> Failed to decrypt secure user data. Error(s):Cookie was tampered with. `
, so they should be used primarily for debugging before deployment. Some messages may be helpful to your user though, for instance: 
`[create_user_create_error] => User name already exists."` or
`[register_new_user_email_used_error] => Email is already in use.`
 Since each error message is a key=>value pair, you could make a whitelist of error messages you deem safe for users to see. After every call to a method that isn’t remote specific you should check for errors by calling the $alpineAuth->getErrors() method, even if the request returned true, to ensure that if there were any errors set they get cleared before the next request. 
 
 While setting up your development environment it’s helpful to print out any errors at the top of your page like so:
```php
//get any errors and display them
$errors = $alpineAuth->getErrors();
if($errors !== false){
	echo "<p style='color:red'>Errors: ";
	print_r($errors);
	echo "</p>";
}else{
	echo "<p style='color:red'>No errors</p>";
}
```

Here is a suggested whitelist for error keys (errors that are safe and should be displayed to the user):
```
login_bfb_delay,login_bfb_catpcha,login_activated_error,login_password_expired_error, authenticate_user_error,create_user_empty_username_error, create_user_empty_password_error,create_user_empty_email_error, create_user_create_error, modify_user_empty_name_error, modify_user_browser_error, set_user_permission_level_admin_error, authenticate_user_password_reset_token_expired_error, reset_user_password_token_activated_error
```



##List of All Methods
**Browser**

* authenticate()
* logInUserBrowser(username, password, captcha = false, throttle_settings = false)
* logOutUserBrowser(username)
* registerNewUserBrowser(username, password, email = null)
* modifyUserBrowser(username,new_info_array, admin_mode = false)
* removeUserBrowser(username, password)
* setUserPermissionLevelBrowser(username, permission_level, admin_mode = false)
* getCurrentUserNameBrowser()
* getCurrentUserIDBrowser()
* getCurrentUserPermissionLevelBrowser()

**Remote**

* logInUserRemote(username, password, throttle_settings = false)
* logOutUserRemote(username, AA_user_data)
* registerNewUserRemote(username, password, email = null)
* modifyUserRemote(username, new_info_array, AA_user_data, admin_mode = false)
* setUserPermissionLevelRemote(username, permission_level, AA_user_data)
* authenticateRemoteUser(username, AA_user_data)

**Other User Methods**

* verifyUser(username)
* authenticateUser(username, password)
* getUserObject(username)
* getUserID(username)
* getUserName(user_id)
* getUserEmail(username)
* getUserPasswordInfoObject(user_id)
* getUserPasswordNumber(user_id)
* getAllUsersObjects()
* getAllUsersTable()

**Password Reset**

* sendUserPasswordResetEmail(username)
* authenticateUserPasswordResetToken(username, reset_token)
* resetUserPassword(username, old_password, reset_token, new_password)

**Account Activation**

* resendUserActivationEmail(username)
* activateUser(username, activation_code)

**Brute Force Attack Prevention**

* getBruteForceBlockerStatus(throttle_settings = null)
* clearBruteForceTable()

**HTML Form Spam Prevention**

*  preventFormSpam(name)
* checkFormSpam(request_type,name)

**General Encryption/Decryption**

* encryptGeneral($name,$raw);
* decryptGeneral($name,$encrypted);

##Configuration
You are given a wide range of options when setting up AlpineAuth, and each should be decided carefully depending on your needs and resources. With that said, the settings that are enabled by defeault (apart from the database settings) should all work without any tweaking. The only things you *need* to set are the database settings and the cryptographic keys/secrets. You can get keys generated on the `/demos/encryptionDemo.php` page to use as your cryptographic secrets and keys. You will want to include the correct redirect URLs for use in password reset and account activation emails as well.

In the `AlpineAuth.class.php` file you will find declarations for the following settings (and some more):

* USE_STATEFUL_AUTH_TOKEN - enables use of stateful auth tokens
* USE_STATELESS_AUTH_TOKEN - enables use of stateless auth tokens
* USE_SESSION_FOR_BROWSER_USER_DATA - whether to use session or cookies only for browser user data (user name, user id, permission level)
* USE_BRUTE_FORCE_PREVENTION - enables brute force prevention
* REQUIRE_EMAIL_ACTIVATION - require user email for account activation before logging in
* EM_SERVICE_NAME - the name of your company, website, app, or game for user in emails
* EM_SENDER_ADDRESS - address that emails are sent from
* ENCRYPT_USER_EMAIL_ADDRESSES - enables encryption of user emails in the database
* STATEFUL_AUTH_TOKEN_LIFETIME_IN_SECONDS - time before stateful auth token expires
* PASSWORD_RESET_TOKEN_LIFETIME_IN_SECONDS - time before password reset token expires
* COOKIE_LIFETIME_IN_SECONDS - time before cookies expire, used for storing user datat and auth tokens
* COOKIE_STORAGE_SECRET - secret value used for verifying HMAC protected cookies
* PASSWORD_AUTO_EXPIRE - enables passwords to auto expire after set time amount
* PASSWORD_LIFETIME_IN_SECONDS - time before password expires
* PASSWORD_HASH_COST - variable CPU cost of password hashing
* SINGLE_STATEFUL_USER_MODE - enforce only a single stateful auth token allowed per account at one time. ie: only one user can be logged in
* PASSWORD_RESET_REDIRECT - URL to link to when sending password reset email
* ACCOUNT_ACTIVATION_REDIRECT - URL to link to when sending account activation email
* STATELESS_AUTH_TOKEN_KEY - key used for hashing stateless auth tokens
* STATELESS_AUTH_TOKEN_SECRET - secret value used for verifying stateless auth tokens

##Third Party Components and Credit
* PHP 5.5 backwards compatibility library for password_* hashing functions [password_compat](https://github.com/ircmaxell/password_compat )
* Encrypted and HMAC protected cookies with [MrClay_CookieStorage](https://code.google.com/p/mrclay/source/browse/trunk/php/MrClay/CookieStorage.php) 
* Stateless authentication token implementation based off work by [Joseph Scott](https://josephscott.org/archives/2013/08/better-stateless-csrf-tokens/)
* FlashMessage class derived from class by Bennett Stone [FlashMessage](http://www.phpdevtips.com/2013/05/simple-session-based-flash-messages/) 
* Email via [PHPMailer](https://github.com/Synchro/PHPMailer)
* Database class (and Eloquent ORM) via Laravel’s [Illuminate Database toolkit](https://github.com/illuminate/database)


##Disclaimer
I am not a professional cryptographer, I'm a programmer. All of the cryptographic functions (encryption/decryption of cookies and emails, hashing of user passwords) are done using third party classes that were created by others who have more expertise in that area. If you think there is a security vulnerability, please submit an issue or let me know what I can do to fix it!
