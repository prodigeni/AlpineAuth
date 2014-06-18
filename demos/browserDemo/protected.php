<?php
	session_start();
	echo "<b>cookies:</b> ";
	print_r($_COOKIE);
	//session_unset();
	echo "<br>";
	echo "<b>session:</b> ";
	print_r($_SESSION);
	echo "<br>";
	echo "<b>post:</b> ";
	print_r($_POST);
	echo "<br>";
	
	//include alpine auth
	include_once( __DIR__.'/../../AlpineAuth.class.php' );
	//create instance of AlpineAuth
	$alpineAuth = new AlpineAuth;
	
	//check if create action is being performed. if so, run that method and display response
	if(isset($_POST['action'])){
		if($_POST['action'] == "logout"){
			//attempt to log in
			$logoutReturn = $alpineAuth->logOutUserBrowser($_POST['username']);
			//redirect to home if success
			if($logoutReturn)
				header( 'Location: login.php' );
		}else if($_POST['action'] == "modify"){
			//attempt to modify user
			//grab values
			$newUserName = $_POST['newUsername'];
			$newEmail = $_POST['newEmail'];
			$username = $_POST['username'];
			//build new info array
			$newInfoArray = array();
			if($newUserName !== "")
				$newInfoArray['name'] = $newUserName;
			if($newEmail !== "")
				$newInfoArray['email'] = $newEmail;
			
			$modifyUserReturn = $alpineAuth->modifyUserBrowser($username,$newInfoArray);
					//check success
			if($modifyUserReturn){
				echo "<h2 style='color:red'>User modified.</h2>";
			}
		}else if($_POST['action'] == "set_permission"){
			//attempt to set permission level
			$newPermission = $_POST['permission_level'];
			$username = $_POST['username'];
			
			$setPermissionReturn = $alpineAuth->setUserPermissionLevelBrowser($username, $newPermission);
			if($setPermissionReturn){
				echo "<h2 style='color:red'>User permission level set.</h2>";
			}
		}
	}

?>

<html>
	<head>
		<link rel="stylesheet" type="text/css" href="../styles.css">
	</head>
	<body>
	<header>
		<h1>AlpineAuth Browser Auth Demo</h1>
	</header>
	<p>This page demonstrates AlpineAuth authenticating a user. You will only see this page if you logged in and are
	authenticated, otherwise you are redirected back to login.</p>
	
	<p>
		<?php
		//check if user is logged in
		if($alpineAuth->authenticate()){
			//user is logged in. display status
			echo '<h1 class="logged_in">you are logged in!</h1>';
		}else{
			//not authorized, redirect to login to let user log in
			header( 'Location: login.php' );
		}
		
		//generate table of all users for demo
		echo '<h2>All Users</h2>'.$alpineAuth->getAllUsersTable();
		
		?>
	</p>
	<?php
	//get any errors and display them
	$errors = $alpineAuth->getErrors();
	if($errors !== false){
		echo "<div class='errors'>ERRORS: ";
		print_r($errors);
		echo "</div>";
	}else{
		echo "<div class='no_errors'>ERRORS: - No errors -</div>";
	}
	?>
	<div class='user_info'>
		<h2>Current user info:</h2>
		<ul>
			<li>username: <?php echo $alpineAuth->getCurrentUsernameBrowser(); ?></li>
			<li>user ID: <?php echo $alpineAuth->getCurrentUserIDBrowser(); ?></li>
			<li>permission level: <?php echo $alpineAuth->getCurrentUserPermissionLevelBrowser(); ?></li>
		</ul>
	</div>
	<form method="post" action="">
		<h2>Modify Current User '<?php echo $alpineAuth->getCurrentUsernameBrowser();?>'</h2>
		<p>Warning: You will need to log in again upon completion if you change your username.</p>
		<input type="hidden" name="username" id="username" value="<?php echo $alpineAuth->getCurrentUsernameBrowser();?>">
		<label for="username">New Email</label>
		<input type="text" name="newEmail" value="">
		<label for="username">New Username</label>
		<input type="text" name="newUsername" value="">
		<input type="hidden" name="action" value="modify">
		<input type="submit"></input>
	</form>
	<form method="post" action="">
		<h2>Set User Permission Level for '<?php echo $alpineAuth->getCurrentUsernameBrowser();?>' </h2>
		<input type="hidden" name="username" id="username" value="<?php echo $alpineAuth->getCurrentUsernameBrowser();?>">
		<input type="text" name="permission_level" value="<?php echo $alpineAuth->getCurrentUserPermissionLevelBrowser();?>">
		<input type="hidden" name="action" value="set_permission">
		<input type="submit"></input>
	</form>
	<form method="post" action="">
		<h2>Log Out User</h2>
		<input type="hidden" name="username" id="username" value="<?php echo $alpineAuth->getCurrentUsernameBrowser();?>">
		<input type="hidden" name="action" value="logout">
		<input type="submit" value="Logout"></input>
	</form>
	</body>
</html>

