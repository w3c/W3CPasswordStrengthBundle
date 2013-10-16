<?php
/**
 * PasswordStrength.php
 *
 * @author Jean-Guilhem Rouel <jean-gui@w3.org>
 * Based on Jeff Todnem's password meter - http://www.passwordmeter.com/
 *
 * @copyright Copyright © 2011 W3C ® (MIT, ERCIM, Keio) {@link http://www.w3.org/Consortium/Legal/2002/ipr-notice-20021231 Usage policies apply}.
 */
namespace W3C\PasswordStrengthBundle\Model;

class PasswordStrength {
    /**
     * Password length
     */
    public $nLength = 0;
    public $sLength = 0;

    /**
     * Number of lowercase alphabetical characters in the password
     */
    public $nAlphaUpperCase = 0;
    public $sAlphaUpperCase = 0;

    /**
     * Number of uppercase alphabetical characters in the password
     */
    public $nAlphaLowerCase = 0;
    public $sAlphaLowerCase = 0;

    /**
     * Number of numbers in the password
     */
    public $nNumber = 0;
    public $sNumber = 0;

    /**
     * Number of symbols in the password
     */
    public $nSymbol = 0;
    public $sSymbol = 0;

    public $nMidChar = 0;
    public $sMidChar = 0;

    public $nAlphasOnly = 0;
    public $sAlphasOnly = 0;

    public $nNumbersOnly = 0;
    public $sNumbersOnly = 0;

    /**
     * Repeated characters (case sensitive)
     */
    public $nRepChar = 0;
    public $sRepChar = 0;

    public $nConsecAlphaUpperCase = 0;
    public $sConsecAlphaUpperCase = 0;

    public $nConsecAlphaLowerCase = 0;
    public $sConsecAlphaLowerCase = 0;

    public $nConsecNumber = 0;
    public $sConsecNumber = 0;

    /**
     * Number of alphabetical characters sequences
     */
    public $nSeqChar = 0;

    public $nSeqAlpha = 0;
    public $sSeqAlpha = 0;

    /**
     * Number of numbers sequences
     */
    public $nSeqNumber = 0;
    public $sSeqNumber = 0;

    /**
     * Global score
     */
    public $score = 0;

    public $nMultAlphaUpperCase;
    public $nMultAlphaLowerCase;
    public $nMultNumber;
    public $nMultSymbol;
    public $nMultMidChar;

    public $nMultConsecAlphaUpperCase;
    public $nMultConsecAlphaLowerCase;
    public $nMultConsecNumber;

    public $nMultSeqAlpha;
    public $nMultSeqNumber;

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

    /**
     * Determine complexity based on overall score
     */
    public function getComplexity() {
        if ($this->score < 20) { return "Very Weak"; }
        else if ($this->score >= 20 && $this->score < 40) { return "Weak"; }
        else if ($this->score >= 40 && $this->score < 60) { return "Sufficient"; }
        else if ($this->score >= 60 && $this->score < 80) { return "Strong"; }
        else if ($this->score >= 80) { return "Very Strong"; }
    }

    public function getNormalizedScore() {
        if ($this->score > 100) {
            return 100;
        } else if ($this->score < 0) {
            return 0;
        }
        return $this->score;
    }

    public function __toString() {
        return $this->getComplexity() . " (" . $this->getNormalizedScore() . ")";
    }

    public function computeScores() {
        $this->setGoodScores();
        $this->setBadScores();

        $this->score = $this->sLength + $this->sAlphaUpperCase + $this->sAlphaLowerCase + $this->sAlphasOnly + $this->sConsecAlphaLowerCase + $this->sConsecAlphaUpperCase + $this->sConsecNumber + $this->sMidChar + $this->sNumber + $this->sNumbersOnly + $this->sRepChar + $this->sSeqAlpha + $this->sSeqNumber + $this->sSymbol;
    }

    private function setGoodScores() {
        $this->sLength = $this->nLength * $this->nMultLength;
        /* General point assignment */
        if ($this->nAlphaUpperCase > 0 && $this->nAlphaUpperCase < $this->nLength) {
            $this->sAlphaUpperCase = ($this->nLength - $this->nAlphaUpperCase) * $this->nMultAlphaUpperCase;
        }
        if ($this->nAlphaLowerCase > 0 && $this->nAlphaLowerCase < $this->nLength) {
            $this->sAlphaLowerCase = ($this->nLength - $this->nAlphaLowerCase) * 2;
        }
        if ($this->nNumber > 0 && $this->nNumber < $this->nLength) {
            $this->sNumber = $this->nNumber * $this->nMultNumber;
        }
        if ($this->nSymbol > 0) {
            $this->sSymbol = $this->nSymbol * $this->nMultSymbol;
        }
        if ($this->nMidChar > 0) {
            $this->sMidChar = $this->nMidChar * $this->nMultMidChar;
        }
    }

    private function setBadScores() {
        /* Point deductions for poor practices */
        if (($this->nAlphaLowerCase > 0 || $this->nAlphaUpperCase > 0) && $this->nSymbol === 0 && $this->nNumber === 0) {  // Only Letters
            $this->nAlphasOnly = $this->nLength;
            $this->sAlphasOnly = - $this->nLength;
        }
        if ($this->nAlphaLowerCase === 0 && $this->nAlphaUpperCase === 0 && $this->nSymbol === 0 && $this->nNumber > 0) {  // Only Numbers
            $this->nNumbersOnly = $this->nLength;
            $this->sNumbersOnly = - $this->nLength;
        }
        if ($this->nRepChar > 0) {  // Same character exists more than once
            $this->sRepChar = - $this->sRepChar;
        }
        if ($this->nConsecAlphaUpperCase > 0) {  // Consecutive Uppercase Letters exist
            $this->sConsecAlphaUpperCase = - $this->nConsecAlphaUpperCase * $this->nMultConsecAlphaUpperCase;
        }
        if ($this->nConsecAlphaLowerCase > 0) {  // Consecutive Lowercase Letters exist
            $this->sConsecAlphaLowerCase = - $this->nConsecAlphaLowerCase * $this->nMultConsecAlphaLowerCase;
        }
        if ($this->nConsecNumber > 0) {  // Consecutive Numbers exist
            $this->sConsecNumber = - $this->nConsecNumber * $this->nMultConsecNumber;
        }
        if ($this->nSeqAlpha > 0) {  // Sequential alpha strings exist (3 characters or more)
            $this->sSeqAlpha = - $this->nSeqAlpha * $this->nMultSeqAlpha;
        }
        if ($this->nSeqNumber > 0) {  // Sequential numeric strings exist (3 characters or more)
            $this->sSeqNumber = - $this->nSeqNumber * $this->nMultSeqNumber;
        }
    }
}

?>