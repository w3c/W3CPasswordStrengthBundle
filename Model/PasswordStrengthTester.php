<?php
/**
 * PasswordStrengthTester.php
 *
 * @author Jean-Guilhem Rouel <jean-gui@w3.org>
 * Based on Jeff Todnem's password meter - http://www.passwordmeter.com/
 *
 * @copyright Copyright © 2011 W3C ® (MIT, ERCIM, Keio) {@link http://www.w3.org/Consortium/Legal/2002/ipr-notice-20021231 Usage policies apply}.
 */
namespace W3C\PasswordStrengthBundle\Model;

class PasswordStrengthTester {

    private $nMultAlphaUpperCase;
    private $nMultAlphaLowerCase;
    private $nMultNumber;
    private $nMultSymbol;
    private $nMultMidChar;

    private $nMultConsecAlphaUpperCase;
    private $nMultConsecAlphaLowerCase;
    private $nMultConsecNumber;

    private $nMultSeqAlpha;
    private $nMultSeqNumber;

    public function __construct($nMultLength=4,
                                $nMultAlphaUpperCase=2, $nMultAlphaLowerCase=2, $nMultNumber=4, $nMultSymbol=6, $nMultMidChar=2,
                                $nMultConsecAlphaUpperCase=2, $nMultConsecAlphaLowerCase=2, $nMultConsecNumber=2,
                                $nMultSeqAlpha=3, $nMultSeqNumber=3) {
        $this->nMultLength = $nMultLength;
        $this->nMultAlphaUpperCase = $nMultAlphaUpperCase;
        $this->nMultAlphaLowerCase = $nMultAlphaLowerCase;
        $this->nMultNumber = $nMultNumber;
        $this->nMultSymbol = $nMultSymbol;
        $this->nMultMidChar = $nMultMidChar;
        $this->nMultConsecAlphaUpperCase = $nMultConsecAlphaUpperCase;
        $this->nMultConsecAlphaLowerCase = $nMultConsecAlphaLowerCase;
        $this->nMultConsecNumber = $nMultConsecNumber;
        $this->nMultSeqAlpha = $nMultSeqAlpha;
        $this->nMultSeqNumber = $nMultSeqNumber;
    }

    public function check($password) {
        $strength = new PasswordStrength($this->nMultLength,
                                         $this->nMultAlphaUpperCase, $this->nMultAlphaLowerCase, $this->nMultNumber, $this->nMultSymbol, $this->nMultMidChar,
                                         $this->nMultConsecAlphaUpperCase, $this->nMultConsecAlphaLowerCase, $this->nMultConsecNumber, $this->nMultSeqAlpha, $this->nMultSeqNumber);

        $this->countChars($password, $strength);

        // Number of consecutive characters of each class
        $this->consecutiveChars($password, $strength);

        // Repeated characters
        $this->repeatedCharacters($password, $strength);

        $strength->computeScores();

        return $strength;
    }


    private function countChars($password, &$strength) {
        $strength->nLength = UTF8Utils::utf8Strlen($password);

        // Number of characters of each class
        $strength->nAlphaLowerCase = preg_match_all('/[a-z]/', $password);
        $strength->nAlphaUpperCase = preg_match_all('/[A-Z]/', $password);
        $strength->nNumber  = preg_match_all('/[0-9]/', $password);
        $strength->nSymbol  = $strength->nLength - preg_match_all('/[a-zA-Z0-9 ]/', $password);

        // Number of non alphabetical chars in the middle of the password
        $strength->nMidChar = $strength->nLength - 2 - preg_match_all('/[a-zA-Z ]/', UTF8Utils::utf8Substr($password, 1, $strength->nLength - 2));
    }

    private function consecutiveChars($password, &$strength) {
        // Number of consecutive characters of each class
        preg_match_all('/[a-z]{2,}/', $password, $matches);
        $strength->nConsecAlphaLowerCase = array_reduce($matches[0], function($result, $item) {
            if(count($item) !== 0) {
                $result = $result + UTF8Utils::utf8Strlen($item) - 1;
            }
            return $result;
        });
        preg_match_all('/[A-Z]{2,}/', $password, $matches);
        $strength->nConsecAlphaUpperCase = array_reduce($matches[0], function($result, $item) {
            if(count($item) !== 0) {
                $result = $result + UTF8Utils::utf8Strlen($item) - 1;
            }
            return $result;
        });
        preg_match_all('/[0-9]{2,}/', $password, $matches);
        $strength->nConsecNumber = array_reduce($matches[0], function($result, $item) {
            if(count($item) !== 0) {
                $result = $result + UTF8Utils::utf8Strlen($item) - 1;
            }
            return $result;
        });
    }

    private function repeatedCharacters($password, &$strength) {
        for($i = 0; $i < $strength->nLength; $i++) {
            $bCharExists = false;
            $char = UTF8Utils::utf8Substr($password, $i, 1);
            for($j = 0; $j < $strength->nLength; $j++) {
                if(($i !== $j) && ($char === UTF8Utils::utf8Substr($password, $j, 1))) {
                    $bCharExists = true;
                    /*
                    Calculate increment deduction based on proximity to identical characters
                    Deduction is incremented each time a new match is discovered
                    Deduction amount is based on total password length divided by the
                    difference of distance between currently selected match
                    */
                    $strength->sRepChar += abs($strength->nLength / ($j - $i));
                }
            }
            if ($bCharExists) {
                $strength->nRepChar++;
                $nUnqChar = $strength->nLength - $strength->nRepChar;
                $strength->sRepChar = ($nUnqChar) ? ceil($strength->sRepChar/$nUnqChar) : ceil($strength->sRepChar);
            }

            if($i < $strength->nLength-2) {
                if(preg_match('/[a-zA-Z]/', $char)) {
                    $char_value = ord(strtoupper($char));
                    $next_char = UTF8Utils::utf8Substr($password, $i+1, 1);
                    $next_char_value = ord(strtoupper($next_char));
                    if($char_value !== 89 && $char_value !== 90 && $char_value+1 === $next_char_value) {
                        $next2_char = UTF8Utils::utf8Substr($password, $i+2, 1);
                        $next2_char_value = ord(strtoupper($next2_char));
                        if($next_char_value+1 === $next2_char_value) {
                            $strength->nSeqAlpha++;
                            $strength->nSeqChar++;
                        }
                    } elseif($char_value !== 65 && $char_value !== 66 && $char_value-1 === $next_char_value) {
                        $next2_char = UTF8Utils::utf8Substr($password, $i+2, 1);
                        $next2_char_value = ord(strtoupper($next2_char));
                        if($next_char_value-1 === $next2_char_value) {
                            $strength->nSeqAlpha++;
                            $strength->nSeqChar++;
                        }
                    }
                } elseif(preg_match('/[0-9]/', $char)) {
                    $next_char = (int)UTF8Utils::utf8Substr($password, $i+1, 1);
                    if((int)$char !== 8 && (int)$char !== 9 && (int)$char+1 === $next_char) {
                        $next2_char = (int)UTF8Utils::utf8Substr($password, $i+2, 1);
                        if($next_char+1 === $next2_char) {
                            $strength->nSeqNumber++;
                            $strength->nSeqChar++;
                        }
                    } elseif((int)$char !== 0 && (int)$char !== 1 && (int)$char-1 === $next_char) {
                        $next2_char = (int)UTF8Utils::utf8Substr($password, $i+2, 1);
                        if($next_char-1 === $next2_char) {
                            $strength->nSeqNumber++;
                            $strength->nSeqChar++;
                        }
                    }
                }
            }
        }
    }
}

?>