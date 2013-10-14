<?php
/**
 * PasswordStrength.php
 *
 * @author Jean-Guilhem Rouel <jean-gui@w3.org>
 * @author Denis Ah-Kang <denis@w3.org>
 * @author Vivien Lacourba <vivien@w3.org>
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
    public $nAlphaUC = 0;
    public $sAlphaUC = 0;

    /**
     * Number of uppercase alphabetical characters in the password
     */
    public $nAlphaLC = 0;
    public $sAlphaLC = 0;

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

    public $nConsecAlphaUC = 0;
    public $sConsecAlphaUC = 0;

    public $nConsecAlphaLC = 0;
    public $sConsecAlphaLC = 0;

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
    public $nScore = 0;

    /**
     * Determine complexity based on overall score
     */
    public function getComplexity() {
        if ($this->nScore < 20) { return "Very Weak"; }
        else if ($this->nScore >= 20 && $this->nScore < 40) { return "Weak"; }
        else if ($this->nScore >= 40 && $this->nScore < 60) { return "Good"; }
        else if ($this->nScore >= 60 && $this->nScore < 80) { return "Strong"; }
        else if ($this->nScore >= 80) { return "Very Strong"; }
    }

    public function getNormalizedScore() {
        if ($this->nScore > 100) {
            return 100;
        } else if ($this->nScore < 0) {
            return 0;
        }
        return $this->nScore;
    }
}

?>