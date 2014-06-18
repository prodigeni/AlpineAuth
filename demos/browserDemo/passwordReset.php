<?php
	session_start();
	echo "<b>cookies:</b> ";
	print_r($_COOKIE);
	/*
	setcookie('stateful_auth_token','',1);
	setcookie('stateless_auth_token','',1);
	session_unset();
	*/
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

	//check if complete password reset action is being performed (form was submitted). if so, run that method and display response
	if(isset($_POST['action'])){
		if($_POST['action'] == "completePasswordReset"){
			$user_name = $_POST['username'];
			$old_password = $_POST['old_pass'];
			$password_reset_token = $_POST['token'];
			$new_password = $_POST['new_pass'];
			
			if($alpineAuth->resetUserPassword($user_name, $old_password, $password_reset_token, $new_password)){
				echo '<h1 style="color:green">password reset successfully</h1>';
			}else{
				echo '<h1 style="color:green">password reset could not be completed</h1>';
			}
		}
	}
	
?>

<html>
	<h1>AlpineAuth Password Reset Demo</h1>
	<p>This page demonstrates AlpineAuth's password reset process. A link to this page would be sent in an email when the user requested a password
	reset.</p>
	<p>
		<?php
		
		//check if logged in, redirect home if so
		if($alpineAuth->authenticate()){
			header( 'Location: home.php' );
			echo '<h1 style="color:red">LOGGED IN</h1>';
		}else{
			echo '<h1 style="color:blue">not logged in</h1>';
		}

		
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
	</p>
	<form method="post" action="">
		<h1>Complete Password Reset</h1>
		<label for="username">Old Password</label>
		<input type="password" name="old_pass" id="old_pass" value="" autocomplete='off'>
		<label for="new_pass">New Password</label>
		<input type="password" name="new_pass" value=""  autocomplete='off'>
		<input type="hidden" name="token" value="<?php echo $_GET['token'];?>">
		<input type="hidden" name="username" value="<?php echo $_GET['u'];?>">
		<input type="hidden" name="action" value="completePasswordReset">
		<input type="submit"></input>
	</form>
</html>

