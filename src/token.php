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

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;


/** \brief Empty token class for SSO login.
 *
 * \details This token will store no data, but will be used to check for a
 *  running SSO session.
 */
class EmptyToken extends AbstractToken
{
	public function getCredentials()
	{
	}
}

?>
