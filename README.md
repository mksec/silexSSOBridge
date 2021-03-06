# SilMod

[![](https://img.shields.io/github/issues-raw/mksec/SilexSSOBridge.svg?style=flat-square)](https://github.com/mksec/SilexSSOBridge/issues) [![GPL license](http://img.shields.io/badge/license-LGPL-blue.svg?style=flat-square)](http://www.gnu.org/licenses/)

[Silex](http://silex.sensiolabs.org/) ``SecurityServiceProvider`` for [Jasny's SSO](https://github.com/jasny/sso).


## Contribute

Anyone is welcome to contribute. Simply fork this repository, make your changes **in an own branch** and create a pull-request for your change. Please do only one change per pull-request.

You found a bug? Please fill out an [issue](https://github.com/mksec/SilexSSOBridge/issues) and include any data to reproduce the bug.

## Usage

Using the SSO bridge is as easy to use as any other AuthenticationServiceProvider - just register and configure in your firewall:

```php
$app = new Silex\Application;

$app->register(new Silex\Provider\SessionServiceProvider);
$app->register(new Silex\Provider\SSO\JasnySSO);

$app->register(new Silex\Provider\SecurityServiceProvider(), array(
	'security.firewalls' => array(
		'login' => array(
			'pattern' => '^/login$'
		),
		'secured_area' => array(
			'pattern' => '^.*$',
			'form' => array(
				'login_path' => '/login',
				'check_path' => '/login_check',
			),
			'logout' => array(
				'logout_path' => '/logout'
			),

			// Settings for Jasny\SSO:
			'sso' => array(
				'server' => "http://localhost:9000",
				'broker' => array(
					'id' => 'Greg',
					'secret' => '7pypoox2pc'
				)
			)
		)
	)
));

```

#### Contributors

[Alexander Haase](https://github.com/alehaa)


## License

SilexSSOBridge is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

SilexSSOBridge is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of **MERCHANTABILITY** or **FITNESS FOR A PARTICULAR PURPOSE**. A Copy of the GPL can be found in the [LICENSE](LICENSE) file.

Copyright (C) 2016 Alexander Haase
