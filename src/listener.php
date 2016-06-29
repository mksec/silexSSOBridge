<?php

/* This file is part of SilexSSOBridge.
 *
 * SilexSSOBridge is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * SilexSSOBridge is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see
 *
 *  http://www.gnu.org/licenses/
 *
 *
 * Copyright (C)
 *  2016 Alexander Haase <ahaase@alexhaase.de>
 */

namespace Silex\Provider\SSO;

use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\
	AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\
	TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;


/** \brief Listener implementation for SSO login.
 *
 * \details This class implements a ListenerInterface to set an \ref EmptyToken.
 *  This token will be used, if no form-input was provided, but to check if the
 *  user has a running SSO session (will be checked by \ref Provider).
 */
class Listener implements ListenerInterface
{
	protected $tokenStorage;
	protected $authenticationManager;


	public function __construct(
		TokenStorageInterface $tokenStorage,
		AuthenticationManagerInterface $authenticationManager)
	{
		$this->tokenStorage = $tokenStorage;
		$this->authenticationManager = $authenticationManager;
	}


	/** \brief Set a new \ref EmptyToken as authenticated token.
	 *
	 * \details This method creates a new \ref EmptyToken and sets it as
	 *  authenticated token. This token will be used, whenever a target behind a
	 *  firewall is accessed, but not if there was form input. With this token
	 *  the \ref Provider is able to check for running SSO sessions of the user.
	 */
	public function handle(GetResponseEvent $event)
	{
		/* If the user is already authenticated, we can skip a new
		 * authentication to save bandwith. */
		$token = $this->tokenStorage->getToken();
		if ($token && $token->isAuthenticated())
			return;


		$authToken = $this->authenticationManager->authenticate(new EmptyToken);
		$this->tokenStorage->setToken($authToken);
	}
}

?>
