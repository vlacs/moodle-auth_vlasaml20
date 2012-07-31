<?php

class vlasaml20 {

    private static $xmlsec1 = "/usr/bin/xmlsec1";

    public static function create_id() {
        $rndChars = 'abcdefghijklmnop';
        $rndId = '';

        for ($i = 0; $i < 40; $i++ ) {
            $rndId .= $rndChars[rand(0,strlen($rndChars)-1)];
        }

        return $rndId;
    }

    public static function get_date_time($timestamp) {
        return gmdate('Y-m-d\TH:i:s\Z', $timestamp);
    }

    private static function mass_str_replace($array, $string) {
        foreach($array as $template_name => $value) {
            $string = str_replace($template_name, $value, $string);
        }
        return $string;
    }

    public static function delete_invalid_saml_requests() {
        return delete_records_select('vlasaml20', 'timeinvalid < ' . time());
    }

    public static function get_authnrequest() {
        global $CFG;
        $request_id = self::create_id();
        $request_record = (object)array(
            'saml_request_idstr' => $request_id,
            'timecreated' => time(),
            'timeinvalid' => time() + 300,
            'ip' => $_SERVER['REMOTE_ADDR'],
            'agent' => substr($_SERVER['HTTP_USER_AGENT'], 200)
        );
        
        $xml = file_get_contents(dirname(__FILE__) . '/xml/authnrequest.xml');
        if(empty($xml)) {
            throw new Exception('Unable to get XML template for SAML authnrequest.');
        }

        if(!insert_record('vlasaml20', $request_record)) {
            error("Unable to insert into vlasaml20.");
        }
        // Get template for authnrequest and subsitute values in.
        $xml = str_replace('{REQUEST_ID}', $request_id, $xml);
        $xml = str_replace('{ISSUE_INSTANT}', self::get_date_time(time()), $xml);
        $xml = str_replace('{ACS_URL}', "$CFG->wwwroot/auth/vlasaml20/login.php", $xml);
        $xml = str_replace('{PROVIDER}', preg_replace('/(http|https):\/\//', '', $CFG->wwwroot), $xml);
        $xml = str_replace('{ISSUER}', preg_replace('/(http|https):\/\//', '', $CFG->wwwroot), $xml);

        return $xml;
    }

    public static function encode_message($msg) {
        $encmsg = gzdeflate($msg);
        $encmsg = base64_encode($encmsg);
        $encmsg = urlencode($encmsg);
        return $encmsg;
    }

    public static function decode_message($msg) {
        $decmsg = base64_decode($msg);
        $infmsg = gzinflate($decmsg);
        if ($infmsg === FALSE) {
            // gzinflate failed, try gzuncompress
            $infmsg = gzuncompress($decmsg);
        };
        return $infmsg;
    }

    public static function process_response($response) {
        global $CFG;
        $response = stripslashes($response);
        // Check signature using xmlsec1 (ewww, but no choice.)
        // TODO!!
        $path = "{$CFG->dataroot}/vlasaml20";
        if(!is_dir($path)) {
            if(!mkdir($path)) {
                throw new Exception("Unable to create dir: $path");
            }
        }
        $file = "$path/".sha1($response . time()).'.xml';
        if(file_exists($file)) {
            unlink($file);
        }
        file_put_contents($file, $response);

        // Do some xmlsec1 stuff to it.
        exec(self::$xmlsec1." --verify $file", $output, $return);
        // dump the file.
        unlink($file);
        if($return) {
            error("(xmlsec1): XML Signature does not verify (bad xmlsig.)");
        }

        // Parse the XML and get the info we need.
        $xml = new SimpleXMLElement($response);

        // We don't need no SimpleXMLElement! Give me an array!
        $simple = self::xml_simplifier($xml);

        $assertion =& $simple['Assertion'];
        $scd_attributes =& $assertion['Subject']['SubjectConfirmation']['SubjectConfirmationData']['@attributes'];

        $saml_data = new stdClass;
        $saml_data->response_id = $simple['@attributes']['ID'];
        $saml_data->time_issued = strtotime($assertion['@attributes']['IssueInstant']);
        $saml_data->username = $assertion['Subject']['NameID'];
        $saml_data->time_lower_bound = strtotime($assertion['Conditions']['@attributes']['NotBefore']);
        $saml_data->time_upper_bound = strtotime($assertion['Conditions']['@attributes']['NotOnOrAfter']);
        $saml_data->request_id = $scd_attributes['InResponseTo'];
        $saml_data->request_timeout_feedback = strtotime($scd_attributes['NotOnOrAfter']);

        // TODO: Make this smarter using a database table or session.
        if ($saml_data->request_timeout_feedback < time()) {
            throw new Exception("SAML Request/Response time issued has expired.");
        }
        if (!$rval = get_record('vlasaml20', 'saml_request_idstr', $saml_data->request_id)) {
            error("The response is responding to a request that doesn't exist in Moodle. It may have timed out.");
        } else {
            delete_records('vlasaml20', 'saml_request_idstr', $saml_data->request_id);
        }
        $user = get_record('user', 'idnumber', $saml_data->username);
        complete_user_login($user);
        add_to_log(SITEID, 'auth-vlasaml20', 'remote saml login', '', 'Successful login', 0, $user->id);

        return true;
    }

    public static function xml_simplifier($simplexmlelement) {
        $obj_vars = get_object_vars($simplexmlelement);
        foreach($obj_vars as &$var) {
            if(is_object($var)) {
                if(get_class($var) == 'SimpleXMLElement') {
                    $var = self::xml_simplifier($var);
                }
            }
        }
        return $obj_vars;
    }
}
