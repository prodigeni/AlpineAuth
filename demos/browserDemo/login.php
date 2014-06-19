<?php
session_start();
	echo "<b>cookies:</b> ";
	print_r($_COOKIE);
	echo "<br>";
	echo "<b>session:</b> ";
	print_r($_SESSION);
	echo "<br>";
	echo "<b>post:</b> ";
	print_r($_POST);
	echo "<br>";
	
	//include alpine auth
	require_once( __DIR__.'/../../AlpineAuth.class.php' );
	//create instance of AlpineAuth
	$alpineAuth = new AlpineAuth;
	
	//check if action is being performed from a form. if so, run that method and display response
	if(isset($_POST['action'])){
		if($_POST['action'] == "login"){
			//attempt to log in
			$loginReturn = $alpineAuth->logInUserBrowser($_POST['username'], $_POST['password']);
			//redirect to home if success
			if($loginReturn)
				header( 'Location: protected.php' );
		}
		else if($_POST['action'] == "register"){
			//first check for form spam
			if($alpineAuth->checkFormSpam('post','registerUser')){
				echo "form spam bot detected!!!<br>";
				return;
			}else{
				echo "NO form spam bot detected<br>";
			}
			//get user info
			$user_name = $_POST['username'];
			$password = $_POST['password'];
			$email = $_POST['email'];
			
			//attempt to register user
			$registerUserReturn = $alpineAuth->registerNewUserBrowser($user_name, $password, $email);
			
			if($registerUserReturn){
				echo "<h2 style='color:red'>User registered.</h2>";
			}else{
			}
			
		}
		else if($_POST['action'] == "remove"){
			//attempt to create user
			$user_name = $_POST['username'];
			$password = $_POST['password'];
			$createUserReturn = $alpineAuth->removeUserBrowser($user_name, $password);
			//check success
			if($createUserReturn){
				echo "<h2 style='color:red'>User removed.</h2>";
			}else{
			}
			
		}else if($_POST['action'] == 'resetPassword'){
			//send a password reset email to the user specified
			$user_name = $_POST['username'];
			if($alpineAuth->sendUserPasswordResetEmail($user_name)){
				echo "<h2 style='color:green'>Password reset email sent.</h2>";
			}else{
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
	
	<p>This page demonstrates how AlpineAuth works within a typical browser environment.</p>
	<p>
		<?php
		//check if logged in/authenticated
		if($alpineAuth->authenticate()){
			//redirect to home if authenticated/logged in
			header( 'Location: protected.php' );
		}else{
			//echo out that we're not logged in
			echo '<h2 class="logged_in">you are NOT logged in</h2>';
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
		<h2>Register New User (send email for activation)</h2>
		<label for="username">Username:</label>
		<input type="text" name="username" id="username">
		<label for="password">Password:</label>
		<input type="password" name="password" id="password">
		<label for="password">Email:</label>
		<input type="text" name="email" id="email">
		<input type="hidden" name="action" value="register">
		<?php echo $alpineAuth->preventFormSpam('registerUser');; ?>
		<input type="submit"></input>
	</form>
	<form method="post" action="">
		<h2>Remove User</h2>
		<label for="username">Username:</label>
		<input type="text" name="username" id="username">
		<label for="password">Password:</label>
		<input type="password" name="password" id="password">
		<input type="hidden" name="action" value="remove">
		<input type="submit"></input>
	</form>
	<form method="post" action="">
		<h2>Recover Password (send email)</h2>
		<label for="username">Username:</label>
		<input type="text" name="username" id="username">
		<input type="hidden" name="action" value="resetPassword">
		<input type="submit"></input>
	</form>
	</body>
</html>

