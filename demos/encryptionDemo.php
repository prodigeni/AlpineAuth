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
	require_once( __DIR__.'/../AlpineAuth.class.php' );
	//create instance of AlpineAuth
	$alpineAuth = new AlpineAuth;
?>

<html>
	<head>
		<link rel="stylesheet" type="text/css" href="styles.css">
	</head>
	<body>
	<header>
		<h1>AlpineAuth Browser Auth Demo</h1>
	</header>
	
	<p>This page demonstrates AlpineAuth encryption/decryption.</p>
	
	<div class='encrypt_demo'>
		<h2>General Encrypt / Decrypt Demo</h2>
		<p>The encryptGeneral() method applies an HMAC and encrypts the string, decryptGeneral() verifies the HMAC and decrypts it.</p>
		<?php
		//demo encryption
		$str = "apples and bananas";
		$encrytped = $alpineAuth->encryptGeneral('test',$str);
		$decrypted = $alpineAuth->decryptGeneral('test',$encrytped);
		?>
		<ol>
			<li><u>Original string:</u> <br><?php echo $str; ?> </li>
			<li><u>Encrypted string:</u> <br><?php echo $encrytped; ?> </li>
			<li><u>Decrypted back to original:</u> <br><?php echo $decrypted; ?> </li>
		</ol>
	</div>
		<div class="random_keys">
		<h2>Here are random strings you can use for your cryptographic secrets/keys.</h2>
		<?php $randomValue = new RandomValue;
			$rand1 = $randomValue->randomTextString(32);
			$rand2 = $randomValue->randomTextString(32);
			$rand3 = $randomValue->randomKey(60);
			$rand4 = $randomValue->randomKey(80);
			$rand5 = $randomValue->randomStrongerKey(80);
			$rand6 = $randomValue->randomStrongerKey(80);
		?>
		<ul>
		<li><?php echo $rand1;?></li>
		<li><?php echo $rand2;?></li>
		<li><?php echo $rand3;?></li>
		<li><?php echo $rand4;?></li>
		<li><?php echo $rand5;?></li>
		<li><?php echo $rand6;?></li>
		</ul>
	</div>
	</body>
</html>

