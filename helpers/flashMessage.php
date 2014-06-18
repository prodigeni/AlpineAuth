<?php
/**
 * Function to create and display error and success messages. 
 * taken from Bennett Stone, http://www.phpdevtips.com/2013/05/simple-session-based-flash-messages/ 
 * modified by Evan Francis
 * @access public
 * @param string session name
 * @param string message
 * @param string display class
 * @return string message
 */
class FlashMessage{
	public static function flash( $name = '', $message = '' )
	{
		//We can only do something if the name isn't empty
		if( !empty( $name ) )
		{
			//No message, create it
			if( !empty( $message ) && empty( $_SESSION[$name] ) )
			{
				if( !empty( $_SESSION[$name] ) )
				{
					unset( $_SESSION[$name] );
				}
	 
				$_SESSION[$name] = $message;
			}
			//Message exists, display it
			elseif( !empty( $_SESSION[$name] ) && empty( $message ) )
			{
				//store value to return before unsetting it
				$flashMessageValue = $_SESSION[$name];
				unset($_SESSION[$name]);
				return $flashMessageValue;
			}
		}
	}
}
?>