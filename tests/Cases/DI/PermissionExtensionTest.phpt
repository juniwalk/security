<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Tests\Cases\DI;

require __DIR__.'/../../bootstrap.php';

use JuniWalk\Security\DI\PermissionExtension;
use Nette\DI\Compiler;
use Nette\DI\Config\Loader;
use Nette\DI\Container;
use Nette\DI\ContainerLoader;
use Nette\Security\Authorizator as AuthorizatorInterface;
use InvalidArgumentException;
use JuniWalk\Security\Authorizator;
use JuniWalk\Security\Providers\FileProvider;
use Nette\DI\Definitions\Statement;
use Nette\DI\InvalidConfigurationException;
use Nette\InvalidStateException;
use Tester\Assert;
use Tester\TestCase;

/**
 * @testCase
 */
final class PermissionExtensionTest extends TestCase
{
	private const File = __DIR__.'/../Providers/fixtures/acl.neon';
	private const Extra = __DIR__.'/../Providers/fixtures/acl.extra.neon';


	/** @param array<string, mixed> $config */
	private function create(array $config, array $services = []): Container
	{
		$loader = new ContainerLoader(sys_get_temp_dir().'/security-tests-'.getmypid(), true);
		$class = $loader->load(function(Compiler $compiler) use ($config, $services) {
			$compiler->addExtension('permission', new PermissionExtension);
			$compiler->addConfig(['permission' => $config, 'services' => $services]);
		}, [$config, $services]);

		return new $class;
	}


	public function testFileSource(): void
	{
		$container = $this->create(['sources' => [new Statement(FileProvider::class, [self::File])]]);
		$acl = $container->getByType(AuthorizatorInterface::class);

		Assert::true($acl->isAllowed('guest', 'Article', 'view'));
		Assert::false($acl->isAllowed('guest', 'System', 'view'));
	}


	public function testAutowiredByClassAndInterface(): void
	{
		$container = $this->create(['sources' => [new Statement(FileProvider::class, [self::File])]]);

		Assert::same(
			$container->getByType(AuthorizatorInterface::class),
			$container->getByType(Authorizator::class),
		);
	}


	public function testNeonSyntaxSources(): void
	{
		$file = sys_get_temp_dir().'/permission-'.getmypid().'.neon';
		file_put_contents($file, "sources:\n\t- ".FileProvider::class.'('.self::File.")\n\t- @extra\n\nstrict: false\n");

		$config = (new Loader)->load($file);
		unlink($file);

		$container = $this->create($config, [
			'extra' => new Statement(FileProvider::class, [self::Extra]),
		]);
		$acl = $container->getByType(AuthorizatorInterface::class);

		Assert::true($acl->isAllowed('guest', 'Article', 'view.archive'));
		Assert::true($acl->isAllowed('admin', 'Article', 'view'));
	}


	public function testMultipleSourcesAreMerged(): void
	{
		$container = $this->create([
			'strict' => false,
			'sources' => [
				new Statement(FileProvider::class, [self::File]),
				new Statement(FileProvider::class, [self::Extra]),
			],
		]);
		$acl = $container->getByType(AuthorizatorInterface::class);

		Assert::true($acl->isAllowed('guest', 'Article', 'view.archive'));
		Assert::true($acl->hasPowerOver('root', 'admin'));
	}


	public function testStrictRejectsDuplicates(): void
	{
		$container = $this->create([
			'sources' => [
				new Statement(FileProvider::class, [self::File]),
				new Statement(FileProvider::class, [self::Extra]),
			],
		]);

		Assert::exception(fn() => $container->getByType(AuthorizatorInterface::class), InvalidArgumentException::class, '%a?%Duplicate role "guest"%a?%');
	}


	public function testRoleEnumIsGeneratedPerSource(): void
	{
		$dir = sys_get_temp_dir().'/security-enums-'.getmypid();
		$container = $this->create([
			'strict' => false,
			'enumDir' => $dir,
			'enumNamespace' => 'JuniWalk\Tests\Generated',
			'sources' => [
				['source' => new Statement(FileProvider::class, [self::File]), 'enum' => 'AppRole'],
				['source' => '@extra', 'enum' => 'Other\ExtraRole'],
				new Statement(FileProvider::class, [self::Extra]),
				new Statement(FileProvider::class, [__DIR__.'/../Providers/fixtures/acl.named.neon']),
			],
		], [
			'extra' => new Statement(FileProvider::class, [self::Extra]),
		]);
		$container->initialize();

		$role = \JuniWalk\Tests\Generated\AppRole::Admin;
		Assert::same('admin', $role->getRoleId());
		Assert::same('enum.role.user', \JuniWalk\Tests\Generated\AppRole::User->label());
		Assert::same(['guest'], \JuniWalk\Tests\Generated\AppRole::getMap()['user']);
		Assert::same(\JuniWalk\Utils\Enums\Color::Success, \JuniWalk\Tests\Generated\AppRole::User->color());
		Assert::same(\JuniWalk\Tests\Generated\AppRole::User, \JuniWalk\Tests\Generated\AppRole::make('user'));
		Assert::true(\JuniWalk\Tests\Generated\AppRole::User instanceof \JuniWalk\Utils\Enums\Interfaces\LabeledEnum);
		Assert::true(is_file($dir.'/AppRole.php'));
		Assert::true(enum_exists(\Other\ExtraRole::class));
		Assert::true(enum_exists(\JuniWalk\Tests\Generated\FileNamedRole::class));
		Assert::false(enum_exists(\JuniWalk\Tests\Generated\AclExtra::class, false));
	}


	public function testMissingEnumFileIsRecreated(): void
	{
		$dir = sys_get_temp_dir().'/security-enums-missing-'.getmypid();
		\JuniWalk\Security\DI\RoleEnumGenerator::load('JuniWalk\Tests\Missing\GoneRole', $dir, new FileProvider(self::File));

		Assert::true(is_file($dir.'/GoneRole.php'));
		Assert::true(enum_exists(\JuniWalk\Tests\Missing\GoneRole::class, false));
	}


	public function testUnnameableValueFails(): void
	{
		Assert::same('MyRole', \JuniWalk\Security\DI\RoleEnumGenerator::toPascalCase('my_role'));
		Assert::exception(fn() => \JuniWalk\Security\DI\RoleEnumGenerator::toPascalCase('3d'), InvalidArgumentException::class);
		Assert::exception(fn() => \JuniWalk\Security\DI\RoleEnumGenerator::toPascalCase('!!'), InvalidArgumentException::class);
	}


	public function testSourcesAreRequired(): void
	{
		Assert::exception(fn() => $this->create([]), InvalidConfigurationException::class);
		Assert::exception(fn() => $this->create(['sources' => []]), InvalidStateException::class);
	}
}

(new PermissionExtensionTest)->run();
