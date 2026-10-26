<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Tests\Cases\Providers;

require __DIR__.'/../../bootstrap.php';

use InvalidArgumentException;
use JuniWalk\Security\Definitions;
use JuniWalk\Security\Providers\CompositeProvider;
use JuniWalk\Security\Resource;
use JuniWalk\Security\Role;
use JuniWalk\Security\Rule;
use JuniWalk\Tests\Files\TestProvider;
use Tester\Assert;
use Tester\TestCase;

/**
 * @testCase
 */
final class CompositeProviderTest extends TestCase
{
	public function testMergesDistinctDefinitions(): void
	{
		$a = new TestProvider(new Definitions([new Role('guest')], [new Resource('Auth')], [new Rule('guest', true, 'Auth')]));
		$b = new TestProvider(new Definitions([new Role('admin', ['guest'])], [new Resource('Web')], [new Rule('admin')]));

		$definitions = (new CompositeProvider([$a, $b]))->load();

		Assert::same(['guest', 'admin'], array_map(fn(Role $r) => $r->name, $definitions->roles));
		Assert::same(['Auth', 'Web'], array_map(fn(Resource $r) => $r->name, $definitions->resources));
		Assert::same(['guest', 'admin'], array_map(fn(Rule $r) => $r->role, $definitions->rules));
	}


	public function testStrictThrowsOnDuplicates(): void
	{
		$a = new TestProvider(new Definitions([new Role('guest')]));
		$b = new TestProvider(new Definitions([new Role('guest')]));
		Assert::exception(fn() => (new CompositeProvider([$a, $b]))->load(), InvalidArgumentException::class, '%a?%Duplicate role "guest"%a?%');

		$a = new TestProvider(new Definitions([], [new Resource('Auth')]));
		$b = new TestProvider(new Definitions([], [new Resource('Auth')]));
		Assert::exception(fn() => (new CompositeProvider([$a, $b]))->load(), InvalidArgumentException::class, '%a?%Duplicate resource "Auth"%a?%');
	}


	public function testLenientMergesDuplicates(): void
	{
		$a = new TestProvider(new Definitions([new Role('user', ['guest'], 'Label')], [new Resource('Web', null, ['view'])]));
		$b = new TestProvider(new Definitions([new Role('user', ['client', 'guest'], null, 'info', 2)], [new Resource('Web', 'Menu', ['view', 'edit'])]));

		$definitions = (new CompositeProvider([$a, $b], strict: false))->load();

		Assert::count(1, $definitions->roles);
		Assert::same(['guest', 'client'], $definitions->roles[0]->parents);
		Assert::same('Label', $definitions->roles[0]->label);
		Assert::same('info', $definitions->roles[0]->color);
		Assert::same(2, $definitions->roles[0]->power);
		Assert::same('Menu', $definitions->resources[0]->parent);
		Assert::same(['view', 'edit'], $definitions->resources[0]->privileges);
	}


	public function testConflictingParentsAlwaysThrow(): void
	{
		$a = new TestProvider(new Definitions([], [new Resource('Web', 'A')]));
		$b = new TestProvider(new Definitions([], [new Resource('Web', 'B')]));

		Assert::exception(fn() => (new CompositeProvider([$a, $b], strict: false))->load(), InvalidArgumentException::class, '%a?%conflicting parents%a?%');
	}
}

(new CompositeProviderTest)->run();
