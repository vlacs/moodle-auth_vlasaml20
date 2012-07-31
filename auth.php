<?php
if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    ///  It must be included from a Moodle page
}

require_once($CFG->libdir.'/authlib.php');

/**
 * Basic auth plugin for SAML. Basically presents local login to require 
 * external IDP intevention.
 */
class auth_plugin_vlasaml20 extends auth_plugin_base {

    function auth_plugin_vlasaml20() {
        $this->authtype = 'vlasaml20';
    }

    /**
     * Always errors, we shouldn't be logging in using a password for 
     * SAML-specific accounts.
     */
    function user_login($username, $password) {
        error('Users using SAML 2.0 auth must login remotely.');
    }

    function fetch_change_password_url() {
        if(!isset($CFG->vlasaml20)) {
            return false;
        }
        if(!isset($CFG->vlasaml20->change_password_url)) {
            return false;
        }
        return $CFG->vlasaml20->change_password_url;
    }

    function can_change_password() {
        global $CFG;
        if($this->fetch_change_password_url()) {
            return true;
        }
        return false;
    }

    function change_password_url() {
        global $CFG;
        return $this->fetch_change_password_url();
    }

    function is_internal() {
        return false;
    }

    function logoutpage_hook() {
        global $redirect, $CFG;
        if(isset($CFG->saml_logout_url)) {
            $redirect = $CFG->saml_logout_url;
        }
    }
}
