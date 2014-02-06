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
use Symfony\Component\Validator\ConstraintValidator;

use W3C\PasswordStrengthBundle\Model\PasswordStrengthTester;

/**
 * @api
 */
class PasswordStrengthValidator extends ConstraintValidator {
    /**
     * {@inheritDoc}
     */
    public function validate($value, Constraint $constraint) {
        if (null === $value || '' === $value || 0 === $value) {
            return;
        }

        $pst = new PasswordStrengthTester();
        $strength = $pst->check($value);

        if ($strength->score < $constraint->minScore) {
            $this->context->addViolation($constraint->message);
        }
    }
}
