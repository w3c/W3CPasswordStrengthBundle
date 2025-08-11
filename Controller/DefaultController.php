<?php

namespace W3C\PasswordStrengthBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use W3C\PasswordStrengthBundle\Model\PasswordStrengthTester;

class DefaultController extends AbstractController {
    public function indexAction(Request $request): JsonResponse
    {
        $pst = new PasswordStrengthTester();
        $strength = $pst->check($request->request->get('password'));

        return new JsonResponse([
            "strength"         => $strength,
            "normalized_score" => $strength->getNormalizedScore(),
            "message"          => $strength->getComplexity()
        ]);
    }
}
