<?php
	echo "<b>post:</b> ";
	print_r($_POST);
	echo "<br>";
	
	//include alpine auth
	include_once( __DIR__.'/../../AlpineAuth.class.php' );
	//create instance of AlpineAuth
	$alpineAuth = new AlpineAuth;
	$remoteResponse = '';
	
	//check if action is being performed from a form. if so, run that method and save response to display on page
	if(isset($_POST['action'])){
		if($_POST['action'] == "login"){
			//attempt to log in
			$loginReturn = $alpineAuth->logInUserRemote($_POST['username'], $_POST['password']);
			$remoteResponse = $loginReturn;
		}
		if($_POST['action'] == "logout"){
			//attempt to log in
			$logoutReturn = $alpineAuth->logOutUserRemote($_POST['username'], $_POST['secure_user_data']);
			$remoteResponse = $logoutReturn;
		}
		else if($_POST['action'] == "register"){
			//get user info
			$user_name = $_POST['username'];
			$password = $_POST['password'];
			$email = $_POST['email'];
			
			//attempt to register user
			$registerUserReturn = $alpineAuth->registerNewUserRemote($user_name, $password, $email);
			$remoteResponse = $registerUserReturn;
		}else if($_POST['action'] == "modify"){
			//attempt to modify user
			//grab values
			$newUserName = $_POST['newUsername'];
			$newEmail = $_POST['newEmail'];
			$secureUserData = $_POST['secure_user_data'];
			//build new info array
			$newInfoArray = array();
			if($newUserName !== "")
				$newInfoArray['name'] = $newUserName;
			if($newEmail !== "")
				$newInfoArray['email'] = $newEmail;
			
			$modifyUserReturn = $alpineAuth->modifyUserRemote($_POST['username'],$newInfoArray,$secureUserData);
			$remoteResponse = $modifyUserReturn;
		}else if($_POST['action'] == "set_permission"){
			//attempt to set permission level
			$newPermission = $_POST['permission_level'];
			$username = $_POST['username'];
			$secureUserData = $_POST['secure_user_data'];
			
			$setPermissionReturn = $alpineAuth->setUserPermissionLevelRemote($username, $newPermission, $secureUserData);
			$remoteResponse = $setPermissionReturn;

		}
	}
?>

<html>
	<head>
		<link rel="stylesheet" type="text/css" href="../styles.css">
	</head>
	<header>
		<h1>AlpineAuth Remote Demo</h1>
	</header>
	<p>This page demonstrates how AlpineAuth works when responding to remote requests, such as a request from a mobile application or game.</p>
	<p>
		
	</p>
	<?php 
		//display json response to remote request if set
		if($remoteResponse !== ''){
			echo "<div class='remote_device'><div class='remote_device_content'><h3>Response to remote request:</h3><br>";
			//$jsonString = json_encode($remoteResponse, JSON_PRETTY_PRINT);
			echo '<pre>';
			echo pretty_json($remoteResponse);;
			//echo $remoteResponse;
			echo "</pre></div></div>";
		}
		
		//display all users table for demo
		echo '<h2>All Users</h2>'.$alpineAuth->getAllUsersTable();
	?>
	<form method="post" action="">
		<h2>Log In User</h2>
		<label for="username">Username:</label>
		<input type="text" name="username" id="username">
		<label for="password">Password:</label>
		<input type="password" name="password" id="password">
		<input type="hidden" name="action" value="login">
		<input type="submit"></input>
	</form>
	<form method="post" action="">
		<h2>Log Out User</h2>
		<label for="username">Username:</label>
		<input type="text" name="username" id="username">
		<label for="password">AA User Data:</label>
		<input type="text" name="secure_user_data" id="secure_user_data">
		<input type="hidden" name="action" value="logout">
		<input type="submit"></input>
	</form>
	<form method="post" action="">
		<h2>Register New User (via email)</h2>
		<label for="username">Username:</label>
		<input type="text" name="username" id="username">
		<label for="password">Password:</label>
		<input type="password" name="password" id="password">
		<label for="password">Email:</label>
		<input type="text" name="email" id="email">
		<input type="hidden" name="action" value="register">
		<?php $alpineAuth->preventFormSpam('registerUser'); ?>
		<input type="submit"></input>
	</form>
	<form method="post" action="">
		<h2>Modify User</h2>
		<label for="username">Current Username:</label>
		<input type="text" name="username" id="username">
		<label for="username">AA User Data:</label>
		<input type="text" name="secure_user_data" id="secure_user_data">
		<label for="username">New Email</label>
		<input type="text" name="newEmail" value="">
		<label for="username">New Username</label>
		<input type="text" name="newUsername" value="">
		<input type="hidden" name="action" value="modify">
		<input type="submit"></input>
	</form>
	<form method="post" action="">
		<h2>Set User Permission Level </h2>
		<label for="username">Username</label>
		<input type="text" name="username" id="username" value="">
		<label for="secure_user_data">AA User Data:</label>
		<input type="text" name="secure_user_data" id="secure_user_data">
		<label for="username">New Permission Level</label>
		<input type="text" name="permission_level" value="">
		<input type="hidden" name="action" value="set_permission">
		<input type="submit"></input>
	</form>
	
</html>

<?php
//pretty print a json string, for demo purposes only
function pretty_json($json) {
    $result      = '';
    $pos         = 0;
    $strLen      = strlen($json);
    $indentStr   = '  ';
    $newLine     = "\n";
    $prevChar    = '';
    $outOfQuotes = true;
 
    for ($i=0; $i<=$strLen; $i++) {
 
        // Grab the next character in the string.
        $char = substr($json, $i, 1);
 
        // Are we inside a quoted string?
        if ($char == '"' && $prevChar != '\\') {
            $outOfQuotes = !$outOfQuotes;
        // If this character is the end of an element, 
        // output a new line and indent the next line.
        } else if(($char == '}' || $char == ']') && $outOfQuotes) {
            $result .= $newLine;
            $pos --;
            for ($j=0; $j<$pos; $j++) {
                $result .= $indentStr;
            }
        }
        // Add the character to the result string.
        $result .= $char;
        // If the last character was the beginning of an element, 
        // output a new line and indent the next line.
        if (($char == ',' || $char == '{' || $char == '[') && $outOfQuotes) {
            $result .= $newLine;
            if ($char == '{' || $char == '[') {
                $pos ++;
            }
            for ($j = 0; $j < $pos; $j++) {
                $result .= $indentStr;
            }
        }
        $prevChar = $char;
    }
 
    return $result;
}

?>