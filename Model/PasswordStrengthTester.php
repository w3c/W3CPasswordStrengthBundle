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
                                $nMultConsecAlphaUC=-2, $nMultConsecAlphaLC=-2, $nMultConsecNumber=-2,
                                $nMultSeqAlpha=-3, $nMultSeqNumber=-3) {
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
        $score = new PasswordStrength();

        $score->nLength = UTF8Utils::utf8_strlen($password);

        // Number of characters of each class
        $score->nAlphaLC = preg_match_all('/[a-z]/', $password);
        $score->nAlphaUC = preg_match_all('/[A-Z]/', $password);
        $score->nNumber  = preg_match_all('/[0-9]/', $password);
        $score->nSymbol  = $score->nLength - preg_match_all('/[a-zA-Z0-9 ]/', $password);

        // Number of non alphabetical chars in the middle of the password
        $score->nMidChar = $score->nLength - 2 - preg_match_all('/[a-zA-Z ]/', UTF8Utils::utf8_substr($password, 1, $score->nLength - 2));

        // Number of consecutive characters of each class
        preg_match_all('/[a-z]{2,}/', $password, $matches);
        $score->nConsecAlphaLC = array_reduce($matches[0], function($result, $item) {
            if(count($item) !== 0) {
                $result = $result + UTF8Utils::utf8_strlen($item) - 1;
            }
            return $result;
        });
        preg_match_all('/[A-Z]{2,}/', $password, $matches);
        $score->nConsecAlphaUC = array_reduce($matches[0], function($result, $item) {
            if(count($item) !== 0) {
                $result = $result + UTF8Utils::utf8_strlen($item) - 1;
            }
            return $result;
        });
        preg_match_all('/[0-9]{2,}/', $password, $matches);
        $score->nConsecNumber = array_reduce($matches[0], function($result, $item) {
            if(count($item) !== 0) {
                $result = $result + UTF8Utils::utf8_strlen($item) - 1;
            }
            return $result;
        });

        // Repeated characters
        for($i = 0; $i < $score->nLength; $i++) {
            $bCharExists = false;
            $char = UTF8Utils::utf8_substr($password, $i, 1);
            for($j = 0; $j < $score->nLength; $j++) {
                if(($i !== $j) && ($char === UTF8Utils::utf8_substr($password, $j, 1))) {
                    $bCharExists = true;
                    /*
                    Calculate icrement deduction based on proximity to identical characters
                    Deduction is incremented each time a new match is discovered
                    Deduction amount is based on total password length divided by the
                    difference of distance between currently selected match
                    */
                    $score->sRepChar += abs($score->nLength / ($j - $i));
                }
            }
            if ($bCharExists) {
                $score->nRepChar++;
                $nUnqChar = $score->nLength - $score->nRepChar;
                $score->sRepChar = ($nUnqChar) ? ceil($score->sRepChar/$nUnqChar) : ceil($score->sRepChar);
            }

            if($i < $score->nLength-2) {
                if(preg_match('/[a-zA-Z]/', $char)) {
                    $char_value = ord(strtoupper($char));
                    $next_char = UTF8Utils::utf8_substr($password, $i+1, 1);
                    $next_char_value = ord(strtoupper($next_char));
                    if($char_value !== 89 && $char_value !== 90 && $char_value+1 === $next_char_value) {
                        $next2_char = UTF8Utils::utf8_substr($password, $i+2, 1);
                        $next2_char_value = ord(strtoupper($next2_char));
                        if($next_char_value+1 === $next2_char_value) {
                            $score->nSeqAlpha++;
                            $score->nSeqChar++;
                        }
                    } elseif($char_value !== 65 && $char_value !== 66 && $char_value-1 === $next_char_value) {
                        $next2_char = UTF8Utils::utf8_substr($password, $i+2, 1);
                        $next2_char_value = ord(strtoupper($next2_char));
                        if($next_char_value-1 === $next2_char_value) {
                            $score->nSeqAlpha++;
                            $score->nSeqChar++;
                        }
                    }
                } elseif(preg_match('/[0-9]/', $char)) {
                    $next_char = (int)UTF8Utils::utf8_substr($password, $i+1, 1);
                    if((int)$char !== 8 && (int)$char !== 9 && (int)$char+1 === $next_char) {
                        $next2_char = (int)UTF8Utils::utf8_substr($password, $i+2, 1);
                        if($next_char+1 === $next2_char) {
                            $score->nSeqNumber++;
                            $score->nSeqChar++;
                        }
                    } elseif((int)$char !== 0 && (int)$char !== 1 && (int)$char-1 === $next_char) {
                        $next2_char = (int)UTF8Utils::utf8_substr($password, $i+2, 1);
                        if($next_char-1 === $next2_char) {
                            $score->nSeqNumber++;
                            $score->nSeqChar++;
                        }
                    }
                }
            }
        }

        /* Modify overall score value based on usage vs requirements */

        /* General point assignment */
        if ($score->nAlphaUC > 0 && $score->nAlphaUC < $score->nLength) {
            $score->sAlphaUC = ($score->nLength - $score->nAlphaUC) * $this->nMultAlphaUC;
        }
        if ($score->nAlphaLC > 0 && $score->nAlphaLC < $score->nLength) {
            $score->sAlphaLC = ($score->nLength - $score->nAlphaLC) * 2;
        }
        if ($score->nNumber > 0 && $score->nNumber < $score->nLength) {
            $score->sNumber = $score->nNumber * $this->nMultNumber;
        }
        if ($score->nSymbol > 0) {
            $score->sSymbol = $score->nSymbol * $this->nMultSymbol;
        }
        if ($score->nMidChar > 0) {
            $score->sMidChar = $score->nMidChar * $this->nMultMidChar;
        }

        /* Point deductions for poor practices */
        if (($score->nAlphaLC > 0 || $score->nAlphaUC > 0) && $score->nSymbol === 0 && $score->nNumber === 0) {  // Only Letters
            $score->nAlphasOnly = $score->nLength;
            $score->sAlphasOnly = - $score->nLength;
        }
        if ($score->nAlphaLC === 0 && $score->nAlphaUC === 0 && $score->nSymbol === 0 && $score->nNumber > 0) {  // Only Numbers
            $score->nNumbersOnly = $score->nLength;
            $score->sNumbersOnly = - $score->nLength;
        }
        if ($score->nRepChar > 0) {  // Same character exists more than once
            $score->sRepChar = - $score->sRepChar;
        }
        if ($score->nConsecAlphaUC > 0) {  // Consecutive Uppercase Letters exist
            $score->sConsecAlphaUC = $score->nConsecAlphaUC * $this->nMultConsecAlphaUC;
        }
        if ($score->nConsecAlphaLC > 0) {  // Consecutive Lowercase Letters exist
            $score->sConsecAlphaLC = $score->nConsecAlphaLC * $this->nMultConsecAlphaLC;
        }
        if ($score->nConsecNumber > 0) {  // Consecutive Numbers exist
            $score->sConsecNumber = $score->nConsecNumber * $this->nMultConsecNumber;
        }
        if ($score->nSeqAlpha > 0) {  // Sequential alpha strings exist (3 characters or more)
            $score->sSeqAlpha = $score->nSeqAlpha * $this->nMultSeqAlpha;
        }
        if ($score->nSeqNumber > 0) {  // Sequential numeric strings exist (3 characters or more)
            $score->sSeqNumber = $score->nSeqNumber * $this->nMultSeqNumber;
        }

        $score->sLength = $score->nLength * $this->nMultLength;

        $score->nScore = $score->sLength + $score->sAlphaUC + $score->sAlphaLC + $score->sAlphasOnly + $score->sConsecAlphaLC + $score->sConsecAlphaUC + $score->sConsecNumber + $score->sMidChar + $score->sNumber + $score->sNumbersOnly + $score->sRepChar + $score->sSeqAlpha + $score->sSeqNumber + $score->sSymbol;

        return $score;
    }

}

?>