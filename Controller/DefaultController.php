<?php

namespace W3C\PasswordStrengthBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use FOS\RestBundle\Controller\Annotations as Rest;
use W3C\PasswordStrengthBundle\Model\PasswordStrengthTester;

class DefaultController extends Controller {
    /**
     * @Route("/test/{password}")
     * @Rest\View
     */
    public function indexAction($password) {
        $pst = new PasswordStrengthTester();
        $strength = $pst->check($password);
        return $strength;
    }
}
