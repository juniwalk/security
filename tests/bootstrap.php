<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

use JuniWalk\Security\Definitions;
use JuniWalk\Security\Resource;
use JuniWalk\Security\Role;
use JuniWalk\Security\Rule;
use Tester\Environment;

if (@!include __DIR__.'/../vendor/autoload.php') {
	echo 'Install Nette Tester using `composer install`';
	exit(1);
}

Environment::setup();

/**
 * @param Rule[] $rules
 */
function createDefinitions(array $rules = []): Definitions
{
	return new Definitions(
		[
			new Role('guest'),
			new Role('user', ['guest'], power: 1),
			new Role('admin', ['user'], power: 3),
			new Role('visitor', ['guest']),
		],
		[
			new Resource('Article', null, ['view.default', 'view.edit', 'edit.active']),
			new Resource('Article:Comment', 'Article'),
			new Resource('System'),
		],
		$rules,
	);
}
