<?php
/**
 * PasswordStrength.php
 *
 * @author Jean-Guilhem Rouel <jean-gui@w3.org>
 *
 * @copyright Copyright © 2011 W3C ® (MIT, ERCIM, Keio) {@link http://www.w3.org/Consortium/Legal/2002/ipr-notice-20021231 Usage policies apply}.
 */
namespace W3C\PasswordStrengthBundle\Component\Validator\Constraints;

use Symfony\Component\Validator\Constraint;

/**
 * @Annotation
 *
 * @api
 */
class PasswordStrength extends Constraint {
    public $message = 'This password is not strong enough';
    public $minScore = 40;

    /**
     * Validator class reference
     * The validator must be defined as a service with this name.
     *
     * @return string
     */
    public function validatedBy()
    {
        return 'w3c.validator.passwordstrength';
    }

    /**
     * field: preferredElement name
     * status: status allowed for the field
     */
    public function getDefaultOption()
    {
        return array('minScore');
    }
}
