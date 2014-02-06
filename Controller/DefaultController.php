<?php

namespace W3C\PasswordStrengthBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use FOS\RestBundle\Controller\Annotations as Rest;
use W3C\PasswordStrengthBundle\Model\PasswordStrengthTester;

class DefaultController extends Controller {
    /**
     * @Rest\View
     */
    public function indexAction() {
        $request = $this->getRequest();
        $pst = new PasswordStrengthTester();
        $strength = $pst->check($request->query->get('password'));

        return array("strength" => $strength,
                     "normalized_score" => $strength->getNormalizedScore(),
                     "message" => $strength->getComplexity());
    }
}
