<?php
/*
*		Class to produce unique values
*		By Evan Francis, 2014
*		
*/
class RandomValue{
	//get a random number
	public function randomNumber(){
		$min  = -9999999;
		$max = 9999999;
		$diff = $max - $min;
		if ($diff < 0 || $diff > 0x7FFFFFFF) {
		throw new RuntimeException("Bad range");
		}
		$bytes = mcrypt_create_iv(4, MCRYPT_DEV_URANDOM);
		if ($bytes === false || strlen($bytes) != 4) {
			throw new RuntimeException("Unable to get 4 bytes");
		}
		$ary = unpack("Nint", $bytes);
		$val = $ary['int'] & 0x7FFFFFFF;   // 32-bit safe                           
		$fp = (float) $val / 2147483647.0; // convert to [0,1]                          
		return round($fp * $diff) + $min;

	}
	//get a random number between two values
	public function randomNumberBetween($min,$max){
		$diff = $max - $min;
		if ($diff < 0 || $diff > 0x7FFFFFFF) {
		throw new RuntimeException("Bad range");
		}
		$bytes = mcrypt_create_iv(4, MCRYPT_DEV_URANDOM);
		if ($bytes === false || strlen($bytes) != 4) {
			throw new RuntimeException("Unable to get 4 bytes");
		}
		$ary = unpack("Nint", $bytes);
		$val = $ary['int'] & 0x7FFFFFFF;   // 32-bit safe                           
		$fp = (float) $val / 2147483647.0; // convert to [0,1]                          
		return round($fp * $diff) + $min;
	}
	
	//get a random string
	public function randomTextString($length = 20){
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$randomString = '';
		for ($i = 0; $i < $length; $i++) {
			$randomString .= $characters[(int)$this->randomNumberBetween(0,strlen($characters)-1)];
		}
		return $randomString;
	}
	
	//get a random key (combination of text and special character)
	public function randomKey($length = 50){
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!$./!$./!$./!$./';
		$randomKey = '';
		for ($i = 0; $i < $length; $i++) {
			$randomKey .= $characters[(int)$this->randomNumberBetween(0,strlen($characters)-1)];
		}
		
		return $randomKey;
	}
	
	//get a random key (combination of text and more special character)
	public function randomStrongerKey($length = 100){
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH2f3[]-*39rs23m]v%$&#!@^#Ir{"_q{=1s9-a?1/V2L^!8e*{&_s$8h>g:FlD4$zUGI#R}:1j_1IJKLMasRZ!$./!$./!$+s*5=[T3pkE%:8d';
		$randomKey = '';
		for ($i = 0; $i < $length; $i++) {
			$randomKey .= $characters[(int)$this->randomNumberBetween(0,strlen($characters)-1)];
		}
		
		return $randomKey;
	}
	
	
}

?>