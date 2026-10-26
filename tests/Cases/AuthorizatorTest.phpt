<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Tests\Cases;

require __DIR__.'/../bootstrap.php';

use InvalidArgumentException;
use JuniWalk\Security\Authorizator;
use JuniWalk\Security\Definitions;
use JuniWalk\Security\Resource;
use JuniWalk\Security\Role;
use JuniWalk\Security\Rule;
use JuniWalk\Tests\Files\TestProvider;
use Nette\Security\Resource as NetteResource;
use Tester\Assert;
use Tester\TestCase;

/**
 * @testCase
 */
final class AuthorizatorTest extends TestCase
{
	private function create(Rule ...$rules): Authorizator
	{
		$provider = new TestProvider(createDefinitions($rules));
		return new Authorizator($provider);
	}


	public function testDefaultDeny(): void
	{
		$acl = $this->create();

		Assert::false($acl->isAllowed('admin', 'Article', 'view'));
		Assert::false($acl->isAllowed(null, 'Article', 'view'));
	}


	public function testUnknownRoleAndResourceDeny(): void
	{
		$acl = $this->create(new Rule('guest', true, 'Article'));

		Assert::false($acl->isAllowed('ghost', 'Article', null));
		Assert::false($acl->isAllowed('guest', 'Ghost', null));
	}


	public function testPrivilegeInheritance(): void
	{
		$acl = $this->create(new Rule('guest', true, 'Article', 'view'));

		Assert::true($acl->isAllowed('guest', 'Article', 'view'));
		Assert::true($acl->isAllowed('guest', 'Article', 'view.files'));
		Assert::false($acl->isAllowed('guest', 'Article', 'edit.active'));
		Assert::false($acl->isAllowed('guest', 'Article', null));
	}


	public function testSpecificPrivilegeOverridesGeneral(): void
	{
		$acl = $this->create(
			new Rule('guest', true, 'Article', 'view'),
			new Rule('guest', false, 'Article', 'view.edit'),
		);

		Assert::true($acl->isAllowed('guest', 'Article', 'view.default'));
		Assert::false($acl->isAllowed('guest', 'Article', 'view.edit'));
	}


	public function testRoleInheritance(): void
	{
		$acl = $this->create(new Rule('guest', true, 'Article', 'view'));

		Assert::true($acl->isAllowed('user', 'Article', 'view.detail'));
		Assert::true($acl->isAllowed('admin', 'Article', 'view.detail'));
	}


	public function testResourceInheritance(): void
	{
		$acl = $this->create(new Rule('guest', true, 'Article', 'view'));

		Assert::true($acl->isAllowed('guest', 'Article:Comment', 'view.default'));
		Assert::false($acl->isAllowed('guest', 'System', 'view'));
	}


	public function testAllResourcesRule(): void
	{
		$acl = $this->create(new Rule('admin'));

		Assert::true($acl->isAllowed('admin', 'System', null));
		Assert::true($acl->isAllowed('admin', 'Article', 'edit.active'));
		Assert::true($acl->isAllowed('admin', null, null));
		Assert::false($acl->isAllowed('user', 'System', null));
	}


	public function testLaterBroaderRuleWins(): void
	{
		$acl = $this->create(
			new Rule('admin', false, 'System'),
			new Rule('admin'),
		);

		Assert::true($acl->isAllowed('admin', 'System', null));
	}


	public function testLaterNarrowerRuleWins(): void
	{
		$acl = $this->create(
			new Rule('admin'),
			new Rule('admin', false, 'System'),
		);

		Assert::false($acl->isAllowed('admin', 'System', null));
		Assert::true($acl->isAllowed('admin', 'Article', 'view'));
	}


	public function testObjectArguments(): void
	{
		$acl = $this->create(new Rule('guest', true, 'Article', 'view'));
		$resource = new class implements NetteResource {
			public function getResourceId(): string
			{
				return 'Article';
			}
		};

		Assert::true($acl->isAllowed(new Role('guest'), $resource, 'view'));
	}


	public function testGetRoles(): void
	{
		$roles = $this->create()->getRoles();

		Assert::same(['guest', 'user', 'admin', 'visitor'], array_keys($roles));
		Assert::same(['guest'], $roles['user']->parents);
		Assert::same('admin', $roles['admin']->getRoleId());
	}


	public function testHasPowerOver(): void
	{
		$acl = $this->create();

		Assert::true($acl->hasPowerOver('admin', 'guest'));
		Assert::true($acl->hasPowerOver('admin', 'admin'));
		Assert::true($acl->hasPowerOver(new Role('user'), new Role('guest')));
		Assert::false($acl->hasPowerOver('guest', 'admin'));
	}


	public function testPowerIsIndependentOfInheritance(): void
	{
		$definitions = new Definitions([
			new Role('low', [], power: 1),
			new Role('high', ['low'], power: 1),
			new Role('boss', [], power: 5),
		]);
		$acl = new Authorizator(new TestProvider($definitions));

		Assert::true($acl->hasPowerOver('low', 'high'));
		Assert::true($acl->hasPowerOver('high', 'low'));
		Assert::true($acl->hasPowerOver('boss', 'high'));
		Assert::false($acl->hasPowerOver('high', 'boss'));
		Assert::false($acl->hasPowerOver('boss', 'ghost'));
		Assert::false($acl->hasPowerOver('ghost', 'boss'));
	}


	public function testRuleValidation(): void
	{
		Assert::exception(fn() => $this->create(new Rule('ghost')), InvalidArgumentException::class, '%a?%unknown role%a?%');
		Assert::exception(fn() => $this->create(new Rule('guest', true, 'Ghost')), InvalidArgumentException::class, '%a?%unknown resource%a?%');
		Assert::exception(fn() => $this->create(new Rule('guest', true, 'Article', 'delete')), InvalidArgumentException::class, '%a?%not defined%a?%');
		Assert::noError(fn() => $this->create(new Rule('guest', true, 'Article', 'view')));
	}


	public function testUndefinedParentFails(): void
	{
		$definitions = new Definitions([new Role('a', ['b'])]);
		Assert::exception(
			static fn() => new Authorizator(new TestProvider($definitions)),
			InvalidArgumentException::class, '%a?%Parent role%a?%'
		);

		$definitions = new Definitions([], [new Resource('a', 'b')]);
		Assert::exception(
			static fn() => new Authorizator(new TestProvider($definitions)),
			InvalidArgumentException::class, '%a?%Parent resource%a?%'
		);
	}


	public function testCircularRolesTerminate(): void
	{
		$definitions = new Definitions([new Role('a', ['b']), new Role('b', ['a'])]);
		$acl = new Authorizator(new TestProvider($definitions));

		Assert::false($acl->isAllowed('a', null, null));
	}
}

(new AuthorizatorTest)->run();
