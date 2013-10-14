<?php
/**
 * PasswordStrengthTester.php
 *
 * @author Jean-Guilhem Rouel <jean-gui@w3.org>
 * @author Denis Ah-Kang <denis@w3.org>
 * @author Vivien Lacourba <vivien@w3.org>
 *
 * @copyright Copyright © 2011 W3C ® (MIT, ERCIM, Keio) {@link http://www.w3.org/Consortium/Legal/2002/ipr-notice-20021231 Usage policies apply}.
 */
namespace W3C\PasswordStrengthBundle\Model;

class PasswordStrengthTester {

    private $nMultAlphaUC;
    private $nMultAlphaLC;
    private $nMultNumber;
    private $nMultSymbol;
    private $nMultMidChar;

    private $nMultConsecAlphaUC;
    private $nMultConsecAlphaLC;
    private $nMultConsecNumber;

    private $nMultSeqAlpha;
    private $nMultSeqNumber;

    public function __construct($nMultLength=4,
                                $nMultAlphaUC=2, $nMultAlphaLC=2, $nMultNumber=4, $nMultSymbol=6, $nMultMidChar=2,
                                $nMultConsecAlphaUC=2, $nMultConsecAlphaLC=2, $nMultConsecNumber=2,
                                $nMultSeqAlpha=3, $nMultSeqNumber=3) {
        $this->nMultLength = $nMultLength;
        $this->nMultAlphaUC = $nMultAlphaUC;
        $this->nMultAlphaLC = $nMultAlphaLC;
        $this->nMultNumber = $nMultNumber;
        $this->nMultSymbol = $nMultSymbol;
        $this->nMultMidChar = $nMultMidChar;
        $this->nMultConsecAlphaUC = $nMultConsecAlphaUC;
        $this->nMultConsecAlphaLC = $nMultConsecAlphaLC;
        $this->nMultConsecNumber = $nMultConsecNumber;
        $this->nMultSeqAlpha = $nMultSeqAlpha;
        $this->nMultSeqNumber = $nMultSeqNumber;
    }

    public function check($password) {
        $strength = new PasswordStrength($this->nMultLength,
                                         $this->nMultAlphaUC, $this->nMultAlphaLC, $this->nMultNumber, $this->nMultSymbol, $this->nMultMidChar,
                                         $this->nMultConsecAlphaUC, $this->nMultConsecAlphaLC, $this->nMultConsecNumber, $this->nMultSeqAlpha, $this->nMultSeqNumber);

        $strength->nLength = UTF8Utils::utf8_strlen($password);

        // Number of characters of each class
        $strength->nAlphaLC = preg_match_all('/[a-z]/', $password);
        $strength->nAlphaUC = preg_match_all('/[A-Z]/', $password);
        $strength->nNumber  = preg_match_all('/[0-9]/', $password);
        $strength->nSymbol  = $strength->nLength - preg_match_all('/[a-zA-Z0-9 ]/', $password);

        // Number of non alphabetical chars in the middle of the password
        $strength->nMidChar = $strength->nLength - 2 - preg_match_all('/[a-zA-Z ]/', UTF8Utils::utf8_substr($password, 1, $strength->nLength - 2));

        // Number of consecutive characters of each class
        preg_match_all('/[a-z]{2,}/', $password, $matches);
        $strength->nConsecAlphaLC = array_reduce($matches[0], function($result, $item) {
            if(count($item) !== 0) {
                $result = $result + UTF8Utils::utf8_strlen($item) - 1;
            }
            return $result;
        });
        preg_match_all('/[A-Z]{2,}/', $password, $matches);
        $strength->nConsecAlphaUC = array_reduce($matches[0], function($result, $item) {
            if(count($item) !== 0) {
                $result = $result + UTF8Utils::utf8_strlen($item) - 1;
            }
            return $result;
        });
        preg_match_all('/[0-9]{2,}/', $password, $matches);
        $strength->nConsecNumber = array_reduce($matches[0], function($result, $item) {
            if(count($item) !== 0) {
                $result = $result + UTF8Utils::utf8_strlen($item) - 1;
            }
            return $result;
        });

        // Repeated characters
        for($i = 0; $i < $strength->nLength; $i++) {
            $bCharExists = false;
            $char = UTF8Utils::utf8_substr($password, $i, 1);
            for($j = 0; $j < $strength->nLength; $j++) {
                if(($i !== $j) && ($char === UTF8Utils::utf8_substr($password, $j, 1))) {
                    $bCharExists = true;
                    /*
                    Calculate icrement deduction based on proximity to identical characters
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
                    $next_char = UTF8Utils::utf8_substr($password, $i+1, 1);
                    $next_char_value = ord(strtoupper($next_char));
                    if($char_value !== 89 && $char_value !== 90 && $char_value+1 === $next_char_value) {
                        $next2_char = UTF8Utils::utf8_substr($password, $i+2, 1);
                        $next2_char_value = ord(strtoupper($next2_char));
                        if($next_char_value+1 === $next2_char_value) {
                            $strength->nSeqAlpha++;
                            $strength->nSeqChar++;
                        }
                    } elseif($char_value !== 65 && $char_value !== 66 && $char_value-1 === $next_char_value) {
                        $next2_char = UTF8Utils::utf8_substr($password, $i+2, 1);
                        $next2_char_value = ord(strtoupper($next2_char));
                        if($next_char_value-1 === $next2_char_value) {
                            $strength->nSeqAlpha++;
                            $strength->nSeqChar++;
                        }
                    }
                } elseif(preg_match('/[0-9]/', $char)) {
                    $next_char = (int)UTF8Utils::utf8_substr($password, $i+1, 1);
                    if((int)$char !== 8 && (int)$char !== 9 && (int)$char+1 === $next_char) {
                        $next2_char = (int)UTF8Utils::utf8_substr($password, $i+2, 1);
                        if($next_char+1 === $next2_char) {
                            $strength->nSeqNumber++;
                            $strength->nSeqChar++;
                        }
                    } elseif((int)$char !== 0 && (int)$char !== 1 && (int)$char-1 === $next_char) {
                        $next2_char = (int)UTF8Utils::utf8_substr($password, $i+2, 1);
                        if($next_char-1 === $next2_char) {
                            $strength->nSeqNumber++;
                            $strength->nSeqChar++;
                        }
                    }
                }
            }
        }

        $strength->computeScores();

        return $strength;
    }
}

?>