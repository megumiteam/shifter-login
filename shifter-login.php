<?php
/**
* Plugin Name: Shifter Login
* Plugin URI: https://github.com/megumiteam/shifter-login
* Description: A magic link login plugin for WordPress sites on Shifter
* Version: 1.0.0
* Author: DigitalCube, Daniel Olson
* Author URI: https://digitalcube.jp
* License: GPL2
* Text Domain: shifter-login
* Domain Path: /languages
*/

/**
 * Definitions
 *
 *
 */
define( 'SHIFTER_LOGIN_VERSION', '1.0.0' );
define( 'SL_PLUGIN_DIR', WP_PLUGIN_DIR . '/' . dirname( plugin_basename( __FILE__ ) ) );
define( 'SL_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

/**
 * Function that initiates the plugin text domain
 *
 * @since v.1.0.6
 *
 * @return void
 */
function sl_load_plugin_textdomain() {
	load_plugin_textdomain( 'shifter-login', false, SL_PLUGIN_URL . '/languages/' );
}
add_action('init', 'sl_load_plugin_textdomain');

/**
 * Checks to see if an account is valid. Either email or username
 *
 * @since v.1.0
 *
 * @return bool / WP_Error
 */
function sl_valid_account( $account ) {
	if( is_email( $account ) ) {
		$account = sanitize_email( $account );
	} else {
		$account = sanitize_user( $account );
	}

	if( is_email( $account ) && email_exists( $account ) ) {
		return $account;
	}

	if( ! is_email( $account ) && username_exists( $account ) ) {
		$user = get_user_by( 'login', $account );
		if( $user ) {
			return $user->data->user_email;
		}
	}

	return new WP_Error( 'invalid_account', __( 'The username or email you provided do not exist.', 'shifter-login' ) );
}

/**
 * Create a unique login link.
 *
 * @since v.1.0
 *
 * @return bool / WP_Error
 */
function sl_magic_link( $email_account = false, $nonce = false ) {

	if ( $email_account  == false ){
		return false;
	}

	$valid_email = sl_valid_account( $email_account  );
	$errors = new WP_Error;
	if (is_wp_error($valid_email)){
		$errors->add('invalid_account', $valid_email->get_error_message());
	} else{
		$unique_url = sl_generate_url( $valid_email , $nonce );
		return $unique_url;
	}

	$error_codes = $errors->get_error_codes();

	if (empty( $error_codes  )){
		return false;
	}else{
		return $errors;
	}

}

/**
 * Generates unique URL based on UID and nonce
 *
 * @since v.1.0
 *
 * @return string
 */
function sl_generate_url( $email = false, $nonce = false ){
	if ( $email  == false ){
		return false;
	}
	/* get user id */
	$user = get_user_by( 'email', $email );
	$token = sl_create_onetime_token( 'sl_'.$user->ID, $user->ID  );

	$arr_params = array( 'sl_error_token', 'uid', 'token', 'nonce' );
	$url = remove_query_arg( $arr_params, sl_curpageurl() );

    $url_params = array('uid' => $user->ID, 'token' => $token, 'nonce' => $nonce);
    $url = add_query_arg($url_params, $url);

	return $url;
}

/**
 * Automatically logs in a user with the correct nonce
 *
 * @since v.1.0
 *
 * @return string
 */
add_action( 'init', 'sl_autologin_via_url' );
function sl_autologin_via_url() {
	if( isset( $_GET['token'] ) && isset( $_GET['uid'] ) && isset( $_GET['nonce'] ) ){
		$uid = sanitize_key( $_GET['uid'] );
		$token = sanitize_key( $_REQUEST['token'] );
		$nonce = sanitize_key( $_REQUEST['nonce'] );

		$hash_meta = get_user_meta( $uid, 'sl_' . $uid, true);
		$hash_meta_expiration = get_user_meta( $uid, 'sl_' . $uid . '_expiration', true);
		$arr_params = array( 'uid', 'token', 'nonce' );
		$current_page_url = remove_query_arg( $arr_params, sl_curpageurl() );

		require_once( ABSPATH . 'wp-includes/class-phpass.php');
		$wp_hasher = new PasswordHash(8, TRUE);
		$time = time();

		if ( ! $wp_hasher->CheckPassword($token . $hash_meta_expiration, $hash_meta) || $hash_meta_expiration < $time || ! wp_verify_nonce( $nonce, 'sl_login_request' ) ){
			wp_redirect( $current_page_url . '?sl_error_token=true' );
			exit;
		} else {
			wp_set_auth_cookie( $uid );
			delete_user_meta($uid, 'sl_' . $uid );
			delete_user_meta($uid, 'sl_' . $uid . '_expiration');

			$total_logins = get_option( 'sl_total_logins', 0);
			update_option( 'sl_total_logins', $total_logins + 1);
			wp_redirect( $current_page_url );
			exit;
		}
	}
}

/**
 * Create a nonce like token that you only use once based on transients
 *
 *
 * @since v.1.0
 *
 * @return string
 */
function sl_create_onetime_token( $action = -1, $user_id = 0 ) {
	$time = time();

	// random salt
	$key = wp_generate_password( 20, false );

	require_once( ABSPATH . 'wp-includes/class-phpass.php');
	$wp_hasher = new PasswordHash(8, TRUE);
	$string = $key . $action . $time;

	$token  = wp_hash( $string );
	$expiration = apply_filters('sl_change_link_expiration', $time + 60*10);
	$expiration_action = $action . '_expiration';

	// we're storing a combination of token and expiration
	$stored_hash = $wp_hasher->HashPassword( $token . $expiration );

	update_user_meta( $user_id, $action , $stored_hash ); // adjust the lifetime of the token. Currently 10 min.
	update_user_meta( $user_id, $expiration_action , $expiration );
	return $token;
}

/**
 * Returns the current page URL
 *
 * @since v.1.0
 *
 * @return string
 */
function sl_curpageurl() {
    $req_uri = $_SERVER['REQUEST_URI'];

    $home_path = trim( parse_url( home_url(), PHP_URL_PATH ), '/' );
    $home_path_regex = sprintf( '|^%s|i', preg_quote( $home_path, '|' ) );

    // Trim path info from the end and the leading home path from the front.
    $req_uri = ltrim($req_uri, '/');
    $req_uri = preg_replace( $home_path_regex, '', $req_uri );
    $req_uri = trim(home_url(), '/') . '/' . ltrim( $req_uri, '/' );

    return $req_uri;
}



// function sl_load_plugin_textdomain()
// function sl_front_end_login()
// function sl_valid_account( $account )
// function sl_magic_link( $email_account = false, $nonce = false )
// function sl_generate_url( $email = false, $nonce = false )
// function sl_autologin_via_url()
// function sl_create_onetime_token( $action = -1, $user_id = 0 )
// function sl_curpageurl()











// WP-CLI
if ( defined('WP_CLI') && WP_CLI ) {
	include __DIR__ . '/cli.php';
}