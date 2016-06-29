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
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Logout\LogoutHandlerInterface;


class LogoutHandler implements LogoutHandlerInterface
{
	protected $broker;


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


	/** \brief Logout the user at SSO server.
	 *
	 * \details For SSO the user must be logged out at the SSO server, too. This
	 *  method handles this after the user has been logged out at this server.
	 */
	public function logout(Request $request,
	                       Response $response,
	                       TokenInterface $token)
	{
		try {
			$this->broker->logout();

		} catch (NotAttachedException $e) {
			throw new SessionUnavailableException('Can\'t attach a session.');

		} catch (SSOException $e) {
			throw new AuthenticationServiceException($e->getMessage());
		}
	}
}

?>
