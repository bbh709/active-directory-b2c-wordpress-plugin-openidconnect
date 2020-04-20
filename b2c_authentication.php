<?php

/**
 * Plugin Name: Microsoft Azure Active Directory B2C Authentication
 * Plugin URI: https://github.com/AzureAD/active-directory-b2c-wordpress-plugin-openidconnect
 * Description: A plugin that allows users to log in using B2C policies
 * Version: 1.0
 * Author: Microsoft
 * Author URI: https://azure.microsoft.com/en-us/documentation/services/active-directory-b2c/
 * License: MIT License (https://raw.githubusercontent.com/AzureAD/active-directory-b2c-wordpress-plugin-openidconnect/master/LICENSE)
 */


// *****************************************************************************************


/**
 * Requires the autoloaders.
 */
require 'autoload.php';
require 'vendor/autoload.php';

/**
 * Defines the response string posted by B2C.
 */
define( 'B2C_RESPONSE_MODE', 'id_token' );

// Adds the B2C Options page to the Admin dashboard, under 'Settings'.
if ( is_admin() ) {
	$b2c_settings_page = new B2C_Settings_Page();
}
$b2c_settings = new B2C_Settings();


// *****************************************************************************************

/**
 * Tries to get the uder based on the b2c user id. If it cannot find it then tries to find it via email
 *
 * @param [type] $b2c_user_id
 * @param [type] $email
 * @return void
 */
function b2c_get_user( $b2c_user_id, $email ) {

	if ( ! empty( $b2c_user_id ) ) {
		// $users = get_users( $args )
		$users = get_users(
			array(
				'meta_key'    => 'b2c_user_id',
				'meta_value'  => $b2c_user_id,
				'number'      => 1,
				'count_total' => false,
			)
		);

		if ( ! empty( $users ) ) {
			// we have the user so return it
			return $users[0];
		}
	}

	// user not found so try to return based on email
	$user = WP_User::get_data_by( 'email', $email );

	// update the user b2c id so that next time we can find it via the b2c user id;
	if ( ! empty( $b2c_user_id ) ) {
		update_user_meta( $user->ID, 'b2c_user_id', $b2c_user_id );
	}

	return $user;
}

/**
 * Returns if the current user logged on with a social login
 *
 * @return void
 */
function b2c_has_social_login() {
	return ! empty( b2c_get_current_user_auth_provider() );
}

/**
 * Get the current user auth provider
 *
 * @return void
 */
function b2c_get_current_user_auth_provider() {
	 $user_id = get_current_user_id();
	if ( $user_id == 0 ) {
		// no user is logged in
		return null;
	}

	return get_user_meta( $user_id, 'b2c_auth_provider', true );
}

/**
 * Generates a username from the email.
 * It uses the value before the '@' as the username. If the username is already in use it appends a counter to it
 *
 * @param [type] $email
 * @return void
 */
function b2c_generate_username( $email ) {
	// get the value before the '@'
	$arr      = explode( '@', $email, 2 );
	$username = $arr[0];

	// check if that username is already in use
	$users       = new WP_User_Query(
		array(
			'search'         => $username . '*',
			'search_columns' => array(
				'user_login',
			),
			'fields'         => array( 'ID' ),
		)
	);
	$users_found = count( $users->get_results() );

	if ( $users_found > 0 ) {
		return $username . $users_found;
	}

	return $username;
}


/**
 * Verifies the id_token that is POSTed back to the web app from the
 * B2C authorization endpoint.
 */
function b2c_verify_token( $return_uri = '' ) {
	try {
		if ( isset( $_POST['error'] ) ) {
			// If user requests the Password Reset flow from a Sign-in/Sign-up flow, the following is returned:
			// Error: access_denied
			// Description: AADB2C90118: The user has forgotten their password.
			if ( preg_match( '/.*AADB2C90118.*/i', $_POST['error_description'] ) ) {
				// user forgot password so redirect to the password reset flow
				b2c_password_reset();
				exit;
			}

			// If user cancels the Sign-up portion of the Sign-in/Sign-up flow or
			// if user cancels the Profile Edit flow, the following is returned:
			// Error: access_denied
			// Description: AADB2C90091: The user has cancelled entering self-asserted information.
			if ( preg_match( '/.*AADB2C90091.*/i', $_POST['error_description'] ) ) {
				// user cancelled profile editing or cancelled signing up
				// so redirect to the home page instead of showing an error
				wp_safe_redirect( site_url() . '/' );
				exit;
			}

			echo 'Authentication error on ' . get_bloginfo( 'name' ) . '.';
			echo '<br>Error: ' . $_POST['error'];
			echo '<br>Description: ' . $_POST['error_description'];
			echo '<br><br><a href="' . site_url() . '">Go to ' . site_url() . '</a>';
			exit;
		}

		if ( isset( $_POST[ B2C_RESPONSE_MODE ] ) ) {
			// Check which authorization policy was used
			switch ( $_POST['state'] ) {
				case 'subscriber':
					$policy = B2C_Settings::$subscriber_policy;
					break;
				case 'admin':
					$policy = B2C_Settings::$admin_policy;
					break;
				case 'edit_profile':
					$policy = B2C_Settings::$edit_profile_policy;
					break;
				case 'signup':
					$policy = B2C_Settings::$signup_policy;
					break;
				default:
					// Not a B2C request, ignore.
					return;
			}

			// Verifies token only if the checkbox "Verify tokens" is checked on the settings page
			$token_checker = new B2C_Token_Checker( $_POST[ B2C_RESPONSE_MODE ], B2C_Settings::$clientID, $policy );
			if ( B2C_Settings::$verify_tokens ) {
				$verified = $token_checker->authenticate();
				if ( $verified == false ) {
					wp_die( 'Token validation error' );
				}
			}

			// Use the email claim to fetch the user object from the WP database
			$email       = $token_checker->get_claim( 'emails' );
			$email       = $email[0];
			$user_b2c_id = $token_checker->get_claim( 'oid' );
			$user        = b2c_get_user( $user_b2c_id, $email );
			// $user = WP_User::get_data_by('email', $email);

			// Get the userID for the user
			if ( $user == false ) { // User doesn't exist yet, create new userID

				// if we are not allowing the automatic creation of new users and we are not coming from the signup policy then throw an error
				if ( ! B2C_Settings::$create_users && $policy != B2C_Settings::$signup_policy ) {
					// user could not be found in WP so logout to clear the b2c cookies
					b2c_logout();
				};

				$name       = $token_checker->get_claim( 'name' );
				$first_name = $token_checker->get_claim( 'given_name' );
				$last_name  = $token_checker->get_claim( 'family_name' );
				$username   = b2c_generate_username( $email );

				$our_userdata = array(
					'ID'              => 0,
					'user_login'      => $username,
					'user_pass'       => null,
					'user_registered' => true,
					'user_status'     => 0,
					'user_email'      => $email,
					'nickname'        => $name,
					'display_name'    => $name,
					'first_name'      => $first_name,
					'last_name'       => $last_name,
				);

				$filtered_user_data = apply_filters( 'b2c_insert_user', $our_userdata, $token_checker->get_payload() );

				// Filter returned false which means we do not want to insert this specific user
				if ( $filtered_user_data === false ) {
					return;
				}

				$userID = wp_insert_user( $filtered_user_data );

				// Allows custom fields sent over the payload to be saved in WordPress
				do_action( 'b2c_new_userdata', $userID, $token_checker->get_payload() );
			} elseif ( $policy == B2C_Settings::$edit_profile_policy ) { // Update the existing user w/ new attritubtes

				$name        = $token_checker->get_claim( 'name' );
				$first_name  = $token_checker->get_claim( 'given_name' );
				$last_name   = $token_checker->get_claim( 'family_name' );
				$user_b2c_id = $token_checker->get_claim( 'object_id' );

				$our_userdata = array(
					'ID'           => $user->ID,
					'display_name' => $name,
					'nickname'     => $name,
					'first_name'   => $first_name,
					'last_name'    => $last_name,
					'user_email'   => $email,
				);

				$filtered_user_data = apply_filters( 'b2c_update_user', $our_userdata, $token_checker->get_payload() );

				// Filter returned false which means we do not want to update this specific user
				if ( $filtered_user_data === false ) {
					return;
				}

				$userID = wp_update_user( $filtered_user_data );

				// Allows custom fields sent over the payload to be updated in WordPress
				do_action( 'b2c_update_userdata', $userID, $token_checker->get_payload() );
			} else {
				$userID = $user->ID;
			}

			// update the provider used by the user
			update_user_meta( $userID, 'b2c_auth_provider', $token_checker->get_claim( 'idp', '' ) );

			// Check if the user is an admin and needs MFA
			$wp_user = new WP_User( $userID );
			if ( in_array( 'administrator', $wp_user->roles ) ) {

				// If user did not authenticate with admin_policy, redirect to admin policy
				if ( mb_strtolower( $token_checker->get_claim( 'tfp' ) ) != mb_strtolower( B2C_Settings::$admin_policy ) ) {
					$b2c_endpoint_handler   = new B2C_Endpoint_Handler( B2C_Settings::$admin_policy );
					$authorization_endpoint = $b2c_endpoint_handler->get_authorization_endpoint( $return_uri ) . '&state=admin';
					if ( $authorization_endpoint ) {
						wp_redirect( $authorization_endpoint );
					}
					exit;
				}
			}

			// Set cookies to authenticate on WP side
			wp_set_auth_cookie( $userID );

			// Redirect to home page
			wp_safe_redirect( site_url() . '/' );
			exit;
		}
	} catch ( Exception $e ) {
		echo $e->getMessage();
		exit;
	}
}

/**
 * Redirects to B2C on a user login request.
 */
function b2c_login( $return_uri = '' ) {

	// C365 Uncomment the line below to allow the standard WP login
	// return;

	try {
		$authorization_endpoint = b2c_get_login_endpoint( $return_uri );
		if ( $authorization_endpoint ) {
			wp_redirect( $authorization_endpoint );
		}
	} catch ( Exception $e ) {
		echo $e->getMessage();
	}
	exit;
}

/**
 * Redirects to B2C on user logout.
 */
function b2c_logout() {
	try {
		$signout_endpoint = b2c_get_logout_endpoint();
		if ( $signout_endpoint ) {
			wp_redirect( $signout_endpoint );
		}
	} catch ( Exception $e ) {
		echo $e->getMessage();
	}
	exit;
}

/**
 * Redirects to B2C's edit profile flow.
 */
function b2c_edit_profile( $return_uri = '' ) {

	// Check to see if user was requesting the edit_profile page, if so redirect to B2C
	/*
	$pagename = $_SERVER['REQUEST_URI'];
	$parts    = explode( '/', $pagename );
	$len      = count( $parts );
	if ( $len > 1 && $parts[ $len - 2 ] == 'wp-admin' && strpos( $parts[ $len - 1 ], 'profile.php' ) === 0 ) {
	*/

	// Return URL for edit_profile endpoint
	try {
		$authorization_endpoint = b2c_get_edit_profile_endpoint( $return_uri );
		if ( $authorization_endpoint ) {
			wp_redirect( $authorization_endpoint );
		}
	} catch ( Exception $e ) {
		echo $e->getMessage();
	}
		exit;
	// }
}

/**
 * Redirects to B2C's signup flow.
 */
function b2c_signup( $return_uri = '' ) {

	try {
		$authorization_endpoint = b2c_get_signup_endpoint( $return_uri );
		if ( $authorization_endpoint ) {
			wp_redirect( $authorization_endpoint );
		}
	} catch ( Exception $e ) {
		echo $e->getMessage();
	}
		exit;

}

/**
 * Redirects to B2C's password reset flow.
 */
function b2c_password_reset( $return_uri = '' ) {
	try {
		$authorization_endpoint = b2c_get_password_reset_endpoint( $return_uri );
		if ( $authorization_endpoint ) {
			wp_redirect( $authorization_endpoint );
		}
	} catch ( Exception $e ) {
		echo $e->getMessage();
	}
	exit;
}

/**
 * Returns the endpoint used to reset a password
 *
 * @param string $return_uri
 * @return mixed false if there is no policy set otherwise the enpoint url
 */
function b2c_get_password_reset_endpoint( $return_uri = '' ) {

	// If no empty policy provided then do nothing;
	if ( empty( B2C_Settings::$password_reset_policy ) ) {
		return false;
	}

	try {
		$b2c_endpoint_handler = new B2C_Endpoint_Handler( B2C_Settings::$password_reset_policy );
		return $b2c_endpoint_handler->get_authorization_endpoint( $return_uri ) . '&state=password_reset';
	} catch ( Exception $e ) {
		echo $e->getMessage();
	}
}

/**
 * Returns the endpoint used to edit the user profile
 *
 * @param string $return_uri
 * @return mixed false if there is no policy otherwise the policy endpoint
 */
function b2c_get_edit_profile_endpoint( $return_uri = '' ) {

	// If no empty policy provided then do nothing;
	if ( empty( B2C_Settings::$edit_profile_policy ) ) {
		return false;
	}

	// Return URL for edit_profile endpoint
	try {
		$b2c_endpoint_handler = new B2C_Endpoint_Handler( B2C_Settings::$edit_profile_policy );
		return $b2c_endpoint_handler->get_authorization_endpoint( $return_uri ) . '&state=edit_profile';
	} catch ( Exception $e ) {
		echo $e->getMessage();
	}
}

/**
 * Returns the endpoint used to logout a user
 *
 * @return mixed false if no policy has been set otherwise the policy endpoint
 */
function b2c_get_logout_endpoint() {

	// If no empty policy provided then do nothing;
	if ( empty( B2C_Settings::$subscriber_policy ) ) {
		return false;
	}

	try {
		$signout_endpoint_handler = new B2C_Endpoint_Handler( B2C_Settings::$subscriber_policy );
		return $signout_endpoint_handler->get_end_session_endpoint();
	} catch ( Exception $e ) {
		echo $e->getMessage();
	}
}

/**
 * Returns the endpoint used to login a user
 *
 * @param string $return_uri
 * @return mixed false if no policy has been set otherwise the policy endpoint
 */
function b2c_get_login_endpoint( $return_uri = '' ) {

	// If no empty policy provided then do nothing;
	if ( empty( B2C_Settings::$subscriber_policy ) ) {
		return false;
	}

	try {
		$b2c_endpoint_handler = new B2C_Endpoint_Handler( B2C_Settings::$subscriber_policy );
		return $b2c_endpoint_handler->get_authorization_endpoint( $return_uri ) . '&state=subscriber';
	} catch ( Exception $e ) {
		echo $e->getMessage();
	}
}

/**
 * Returns the endpoint used to login a user
 *
 * @param string $return_uri
 * @return mixed false if no policy has been set otherwise the policy endpoint
 */
function b2c_get_signup_endpoint( $return_uri = '' ) {

	// If no empty policy provided then do nothing;
	if ( empty( B2C_Settings::$signup_policy ) ) {
		return false;
	}

	try {
		$b2c_endpoint_handler = new B2C_Endpoint_Handler( B2C_Settings::$signup_policy );
		return $b2c_endpoint_handler->get_authorization_endpoint( $return_uri ) . '&state=signup';
	} catch ( Exception $e ) {
		echo $e->getMessage();
	}
}



/**
 * Hooks onto the WP login action, so when user logs in on WordPress, user is redirected
 * to B2C's authorization endpoint.
 */
add_action( 'wp_authenticate', 'b2c_login' );

/**
 * Hooks onto the WP lost password action, so user is redirected
 * to B2C's password reset endpoint.
 *
 * example.com/wp-login.php?action=lostpassword
 */
add_action( 'login_form_lostpassword', 'b2c_password_reset' );

/**
 * Hooks onto the WP page load action, so when user request to edit their profile,
 * they are redirected to B2C's edit profile endpoint.
 */
// add_action( 'wp_loaded', 'b2c_edit_profile' );

/**
 * Hooks onto the WP page load action. When B2C redirects back to WordPress site,
 * if an ID token is POSTed to a special path, b2c-token-verification, this verifies
 * the ID token and authenticates the user.
 */
add_action( 'wp_loaded', 'b2c_verify_token' );

/**
 * Hooks onto the WP logout action, so when a user logs out of WordPress,
 * they are redirected to B2C's logout endpoint.
 */
add_action( 'wp_logout', 'b2c_logout' );
