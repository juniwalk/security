<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Tests\Cases\Providers;

require __DIR__.'/../../bootstrap.php';

use InvalidArgumentException;
use JuniWalk\Security\Authorizator;
use JuniWalk\Security\Providers\FileProvider;
use Tester\Assert;
use Tester\TestCase;

/**
 * @testCase
 */
final class FileProviderTest extends TestCase
{
	public function testNeon(): void
	{
		$definitions = (new FileProvider(__DIR__.'/fixtures/acl.neon'))->load();

		Assert::count(3, $definitions->roles);
		Assert::same(['guest'], $definitions->roles[1]->parents);
		Assert::same('enum.role.user', $definitions->roles[1]->label);
		Assert::same('success', $definitions->roles[1]->color);
		Assert::same(1, $definitions->roles[1]->power);
		Assert::same(0, $definitions->roles[0]->power);
		Assert::null($definitions->roles[0]->color);
		Assert::same('guest', $definitions->roles[0]->getLabel());
		Assert::same(['user'], $definitions->roles[2]->parents);
		Assert::count(6, $definitions->resources);

		$resources = [];
		foreach ($definitions->resources as $resource) {
			$resources[$resource->name] = $resource;
		}

		Assert::null($resources['Menu:Content']->parent);
		Assert::same('Menu:Content', $resources['Article']->parent);
		Assert::same(['view.default', 'view.edit', 'edit.active'], $resources['Article']->privileges);
		Assert::same('Article', $resources['Article:Comment']->parent);
		Assert::same(['view'], $resources['Page']->privileges);
		Assert::same('System', $resources['System:Log']->parent);
		Assert::count(4, $definitions->rules);
		Assert::false($definitions->rules[3]->allowed);
	}


	public function testNeonWorksWithAuthorizator(): void
	{
		$acl = new Authorizator(new FileProvider(__DIR__.'/fixtures/acl.neon'));

		Assert::true($acl->isAllowed('guest', 'Article:Comment', 'view.edit'));
		Assert::false($acl->isAllowed('guest', 'Article', 'edit.active'));
		Assert::true($acl->isAllowed('user', 'Article', 'edit.active'));
		Assert::true($acl->isAllowed('admin', 'Article', 'edit.active'));
		Assert::false($acl->isAllowed('admin', 'System', 'view'));
		Assert::false($acl->isAllowed('admin', 'System:Log', 'view'));
		Assert::true($acl->isAllowed('admin', 'Page', 'view'));
	}


	public function testStructuredRules(): void
	{
		$definitions = (new FileProvider(__DIR__.'/fixtures/acl.structured.neon'))->load();
		$rules = array_map(fn($r) => [$r->role, $r->allowed, $r->resource, $r->privilege], $definitions->rules);

		Assert::same([
			['guest', true, 'Article', 'view'],
			['user', true, 'Article', 'edit.active'],
			['user', true, 'Page', null],
			['admin', true, null, null],
			['guest', false, null, 'edit'],
			['admin', false, 'System', null],
		], $rules);
	}


	public function testStructuredRulesWorkWithAuthorizator(): void
	{
		$acl = new Authorizator(new FileProvider(__DIR__.'/fixtures/acl.structured.neon'));

		Assert::true($acl->isAllowed('guest', 'Article', 'view.default'));
		Assert::false($acl->isAllowed('guest', 'Article', 'edit.active'));
		Assert::true($acl->isAllowed('user', 'Article', 'edit.active'));
		Assert::true($acl->isAllowed('user', 'Page', 'view'));
		Assert::true($acl->isAllowed('admin', 'Page', 'view'));
		Assert::false($acl->isAllowed('admin', 'System', 'view'));
	}


	public function testUnknownRulesSection(): void
	{
		$file = sys_get_temp_dir().'/acl-'.getmypid().'.php';
		file_put_contents($file, '<?php return ["roles" => ["a" => null], "rules" => ["permit" => []]];');

		Assert::exception(fn() => (new FileProvider($file))->load(), InvalidArgumentException::class, '%a?%unknown section "permit"%a?%');
		unlink($file);
	}


	public function testNestedRuleCoversChildren(): void
	{
		$data = ['roles' => ['guest' => null], 'resources' => ['Menu' => ['Home' => null, 'Product' => ['view']]], 'rules' => [['role' => 'guest', 'resource' => 'Menu']]];
		$file = sys_get_temp_dir().'/acl-'.getmypid().'.php';
		file_put_contents($file, '<?php return '.var_export($data, true).';');

		$acl = new Authorizator(new FileProvider($file));
		unlink($file);

		Assert::true($acl->isAllowed('guest', 'Home', null));
		Assert::true($acl->isAllowed('guest', 'Product', 'view'));
	}


	public function testUnknownSection(): void
	{
		$file = sys_get_temp_dir().'/acl-'.getmypid().'.php';
		file_put_contents($file, '<?php return ["resource" => []];');

		Assert::exception(fn() => (new FileProvider($file))->load(), InvalidArgumentException::class, '%a?%unknown section "resource"%a?%');
		unlink($file);
	}


	public function testJson(): void
	{
		$definitions = (new FileProvider(__DIR__.'/fixtures/acl.json'))->load();

		Assert::count(2, $definitions->roles);
		Assert::same(['view'], $definitions->resources[0]->privileges);
		Assert::count(1, $definitions->rules);
	}


	public function testPhp(): void
	{
		$definitions = (new FileProvider(__DIR__.'/fixtures/acl.php'))->load();

		Assert::count(1, $definitions->roles);
		Assert::true($definitions->rules[0]->allowed);
		Assert::null($definitions->rules[0]->privilege);
	}


	public function testInvalidFiles(): void
	{
		Assert::exception(fn() => (new FileProvider(__DIR__.'/missing.neon'))->load(), InvalidArgumentException::class, '%a?%does not exist%a?%');
		Assert::exception(fn() => (new FileProvider(__DIR__.'/fixtures/acl.txt'))->load(), InvalidArgumentException::class, '%a?%Unsupported%a?%');
	}
}

(new FileProviderTest)->run();
