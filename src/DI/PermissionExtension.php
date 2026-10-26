<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security\DI;

use JuniWalk\Security\Authorizator;
use JuniWalk\Security\Provider;
use JuniWalk\Security\Providers\CompositeProvider;
use Nette\DI\CompilerExtension;
use Nette\DI\Definitions\Reference;
use Nette\DI\Definitions\Statement;
use Nette\InvalidStateException;
use Nette\Schema\Expect;
use Nette\Schema\Schema;
use stdClass;

use function array_map;
use function array_values;
use function assert;
use function str_starts_with;
use function substr;

/**
 * Sources are services, class names or statements implementing Provider, e.g.
 *
 * permission:
 *   strict: true
 *   sources:
 *     - JuniWalk\Security\Providers\FileProvider(%appDir%/config/permission.neon)
 *     - @customProvider
 */
final class PermissionExtension extends CompilerExtension
{
	public function getConfigSchema(): Schema
	{
		return Expect::structure([
			'sources' => Expect::arrayOf(Expect::anyOf(Expect::string(), Expect::type(Statement::class)))->required(),
			'strict' => Expect::bool(true),
		]);
	}


	public function loadConfiguration(): void
	{
		$builder = $this->getContainerBuilder();
		$config = $this->getConfig();
		assert($config instanceof stdClass);

		if (empty($config->sources)) {
			throw new InvalidStateException("Option '{$this->name}.sources' needs at least one source.");
		}

		$sources = array_map(static fn(Statement|string $source): Statement|Reference => match (true) {
			$source instanceof Statement => $source,
			str_starts_with($source, '@') => new Reference(substr($source, 1)),
			default => new Statement($source),
		}, array_values($config->sources));

		$provider = $builder->addDefinition($this->prefix('provider'))
			->setType(Provider::class)
			->setFactory(CompositeProvider::class, [$sources, $config->strict]);

		$builder->addDefinition($this->prefix('authorizator'))
			->setFactory(Authorizator::class, [$provider]);
	}
}
