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

use Pimple\Container;
use Pimple\ServiceProviderInterface;


/** \brief Factory to register JasnySSO authentication.
 */
class JasnySSO implements ServiceProviderInterface
{
	public function register(Container $app)
	{
		$app['security.authentication_listener.factory.sso'] = $app->protect(
			function ($name, $options) use ($app) {
				$app['security.authentication_provider.'.$name.'.sso'] =
					function () use ($app, $options) {
						return new Provider($options['server'],
							$options['broker']['id'],
							$options['broker']['secret']);
					};

				$app['security.authentication_listener.'.$name.'.sso'] =
					function () use ($app) {
						return new Listener(
							$app['security.token_storage'],
							$app['security.authentication_manager']
						);
					};

				return array(
					'security.authentication_provider.'.$name.'.sso',
					'security.authentication_listener.'.$name.'.sso',
					null,
					'form'
				);
			}
		);
	}
}

?>
