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

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\
	AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\
	TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;


/** \brief Listener implementation for SSO login.
 *
 * \details This class implements the Silex ListenerInterface to fetch the users
 *  credentials and store them in a token.
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


	public function handle(GetResponseEvent $event)
	{
		$request = $event->getRequest();

		$username = $request->get('username');
		$password = $request->get('password');

		if (empty($username) || empty($password))
			return;


		$token = new UsernamePasswordToken($username, $password, "sso");

		try {
			$authToken = $this->authenticationManager->authenticate($token);
			$this->tokenStorage->setToken($authToken);

			return;

		} catch (AuthenticationException $failed) {
		}
	}
}

?>
