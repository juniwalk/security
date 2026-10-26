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


	public function testSourcesAreRequired(): void
	{
		Assert::exception(fn() => $this->create([]), InvalidConfigurationException::class);
		Assert::exception(fn() => $this->create(['sources' => []]), InvalidStateException::class);
	}
}

(new PermissionExtensionTest)->run();
