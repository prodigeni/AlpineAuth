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
	include_once( __DIR__.'/../../AlpineAuth.class.php' );
	//create instance of AlpineAuth
	$alpineAuth = new AlpineAuth;
	
	$message = '';
	
	//grab parameters from URL
	if(isset($_GET['code']) && isset($_GET['u'])){
		$user_name = $_GET['u'];
		$activation_code = $_GET['code'];
		$activationReturn = $alpineAuth->activateUser($user_name,$activation_code);
		if($activationReturn){
			$message = '<h1 style="color:green">Account activated!</h1>';
		}else{
			$message = '<h1 style="color:green">Oops! There was a problem activating your account.</h1>';
		}
	}
	
?>

<html>
	<h1>AlpineAuth Account Activation Demo</h1>
	<?php echo $message; ?>
	
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
</html>

