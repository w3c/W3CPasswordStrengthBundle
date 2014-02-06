<?php
/**
 * UTF8Utils.php
 *
 * @author Jean-Guilhem Rouel <jean-gui@w3.org>
 *
 * @copyright Copyright © 2011 W3C ® (MIT, ERCIM, Keio) {@link http://www.w3.org/Consortium/Legal/2002/ipr-notice-20021231 Usage policies apply}.
 */
namespace W3C\PasswordStrengthBundle\Model;

class UTF8Utils {
    public static function utf8Strlen($string) {
        if (function_exists('grapheme_strlen')) {
            return grapheme_strlen($string);
        } elseif (function_exists('mb_strlen')) {
            return mb_strlen($string, 'UTF-8');
        } else {
            return strlen($string);
        }
    }

    public static function utf8Substr($string , $start, $length=NULL) {
        if (function_exists('grapheme_substr')) {
            return grapheme_substr($string, $start, $length);
        } elseif (function_exists('mb_sustr')) {
            $length = mb_substr($string, $start, $length, 'UTF-8');
        } else {
            $length = substr($string, $start, $length);
        }
    }
}

?>