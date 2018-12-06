<?php

class Shifter_Login_CLI {
 
	/**
	 * Create magic link
	 *
	 * ## OPTIONS
	 * <user_email>
	 * user_email
	 *
 	 *
 	 * ## EXAMPLES
 	 *
 	 * wp shifter-login login <user_email>
   *
   * @param string $args: WP-CLI Command Name
	 * @param string $assoc_args: WP-CLI Command Option
	 * @since 2.3.0
	 */
  
  function login( $args, $assoc_args ) {

    $email_account = $assoc_args['user_email'];
    
    // Check for valid user_email param
    if (!filter_var($email_account, FILTER_VALIDATE_EMAIL)) {
      WP_CLI::error( '--user_email must be a valid and registered user email address' );
    }

    // Check for a valid registered user
    if ( is_wp_error( $result = sl_valid_account($email_account) ) ) {
      $error_string = $result->get_error_message();
      WP_CLI::error( $error_string );
    }

    $output = sl_magic_link($email_account, wp_create_nonce('sl_passwordless_login_request'));

    WP_CLI::success( $output );

	}
 
}

WP_CLI::add_command( 'shifter-login', 'Shifter_Login_CLI' );