<?php

require_once(dirname(dirname(dirname(__FILE__))) . '/config.php');
require_once(dirname(__FILE__) . '/lib.php');

// Step 1: Create SAML Request
if(!$response = optional_param('SAMLResponse', false, PARAM_RAW)) {
    $request_xml = vlasaml20::get_authnrequest();
    $encoded_saml = vlasaml20::encode_message($request_xml);
    $wantsurl = $SESSION->wantsurl;
    unset($SESSION->wantsurl);
    if(!$wantsurl) {
        $wantsurl = $CFG->wwwroot;
    }
    $url = 'https://portaltest1.vlacs.org/idp/saml20?RelayState='.urlencode($wantsurl);
    $url .= "&SAMLRequest={$encoded_saml}";

    redirect($url);
}

vlasaml20::delete_invalid_saml_requests();
vlasaml20::process_response($response);
redirect(required_param('RelayState', PARAM_RAW));
