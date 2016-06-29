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

use Jasny\SSO\Broker;
use Jasny\SSO\NotAttachedException;
use Jasny\SSO\Exception as SSOException;
use Symfony\Component\Security\Core\Authentication\Provider\
	AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Exception\SessionUnavailableException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;


class Provider implements AuthenticationProviderInterface
{
	private $broker;


	/** \brief Constructor.
	 *
	 * \details Creates a new broker.
	 *
	 *
	 * \param sso_url URL to SSO service.
	 * \param broker_id ID of this broker.
	 * \param broker_secret Shared secret of this broker.
	 */
	public function __construct(string $sso_url,
	                            string $broker_id,
	                            string $broker_secret)
	{
		$this->broker = new Broker($sso_url, $broker_id, $broker_secret);
	}


	/** \brief Check wheter \p token can be authorized by the SSO service.
	 *
	 *
	 * \param token The token to be authenticated.
	 */
	public function supports(TokenInterface $token)
	{
		return $token instanceof UsernamePasswordToken;
	}


	/** \brief Authenticate \p token via SSO server.
	 *
	 * \details Authenticate username and credentials stored in \p token via the
	 *  SSO server. If the user has no session attached to the SSO server, a new
	 *  session will be initiated.
	 *
	 *
	 * \param token The token to be authenticated.
	 */
	public function authenticate(TokenInterface $token)
	{
		/* Attach our session to the user's session on the SSO server. This will
		 * redirect the user to the SSO server, if his session is not attached
		 * already. The user will return to the current accessed URL after this
		 * operation.
		 *
		 * Doing this step here and not in the constructor ensures, that a
		 * session will be attached only if it's required. This avoids overhead
		 * for users that don't want to login. */
		$this->broker->attach(true);


		/* Try to authorize the user via the SSO server. */
		try {
			$user = $this->broker->login($token->getUsername(),
			                             $token->getCredentials());

			if ($user)
				return new UsernamePasswordToken($token->getUsername(), null,
					'sso', isset($user['roles']) ?
						$user['roles'] : ['ROLE_USER']);

		} catch (NotAttachedException $e) {
			throw new SessionUnavailableException('Can\'t attach a session.');

		} catch (SSOException $e) {
			throw new AuthenticationServiceException($e->getMessage());
		}
	}
}

?>
