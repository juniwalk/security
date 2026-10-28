<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security\DI;

use JuniWalk\Security\Authorizator;
use JuniWalk\Security\Provider;
use JuniWalk\Security\Providers\CompositeProvider;
use JuniWalk\Security\Providers\FileProvider;
use JuniWalk\Security\Tracy\AuthorizatorPanel;
use Nette\DI\CompilerExtension;
use Nette\DI\Definitions\Reference;
use Nette\DI\Definitions\ServiceDefinition;
use Nette\DI\Definitions\Statement;
use Nette\InvalidStateException;
use Nette\PhpGenerator\ClassType;
use Nette\Schema\Expect;
use Nette\Schema\Schema;
use Tracy\Bar;
use stdClass;

use function array_values;
use function assert;
use function class_exists;
use function is_a;
use function is_string;
use function ltrim;
use function str_contains;
use function str_starts_with;
use function substr;
use function sys_get_temp_dir;

/**
 * Sources are services, class names or statements implementing Provider, e.g.
 *
 * permission:
 *   strict: true
 *   enumNamespace: App\Security      # default JuniWalk\Security\Roles
 *   enumDir: %appDir%/Security       # default %tempDir%/cache/JuniWalk.Security.Roles
 *   sources:
 *     - JuniWalk\Security\Providers\FileProvider(%appDir%/config/permission.neon)
 *     - @customProvider
 *     - source: JuniWalk\Security\Providers\FileProvider(%appDir%/config/admin.neon)
 *       enum: AdminRole              # overrides the name of generated App\Security\AdminRole
 *
 * A provider names its enum itself (Provider::getEnumName(), FileProvider reads the "enum" key of its file),
 * the "enum" option of a source overrides the name, "false" disables it. Providers are built at compile time.
 */
final class PermissionExtension extends CompilerExtension
{
	private ?string $panel = null;

	/** @var array<int, string|bool> enum setting by source index */
	private array $enums = [];

	/** @var array<int, Statement|Reference> */
	private array $sources = [];

	/** @var array<string, array{Statement, string}> provider and directory by enum class */
	private array $enumProviders = [];


	public function getConfigSchema(): Schema
	{
		$source = Expect::anyOf(Expect::string(), Expect::type(Statement::class));

		return Expect::structure([
			'sources' => Expect::arrayOf(Expect::anyOf($source, Expect::structure([
				'source' => Expect::anyOf(Expect::string(), Expect::type(Statement::class))->required(),
				'enum' => Expect::anyOf(Expect::string(), Expect::bool())->default(null),
			])))->required(),
			'strict' => Expect::bool(true),
			'enumNamespace' => Expect::string('JuniWalk\\Security\\Roles'),
			'enumDir' => Expect::string(),
			'debugger' => Expect::bool()->default(null),
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

		$sources = [];

		foreach (array_values($config->sources) as $index => $source) {
			if ($source instanceof stdClass) {
				$this->enums[$index] = $source->enum;
				$source = $source->source;
			}

			$sources[$index] = match (true) {
				$source instanceof Statement => $source,
				str_starts_with($source, '@') => new Reference(substr($source, 1)),
				default => new Statement($source),
			};
		}

		$this->sources = $sources;

		$provider = $builder->addDefinition($this->prefix('provider'))
			->setType(Provider::class)
			->setFactory(CompositeProvider::class, [$sources, $config->strict]);

		$builder->addDefinition($this->prefix('authorizator'))
			->setFactory(Authorizator::class, [$provider]);

		// ? Panel is enabled by default in debug mode, explicit "debugger" option overrides it
		$debugger = $config->debugger ?? ($builder->parameters['debugMode'] ?? false);

		if ($debugger && class_exists(Bar::class)) {
			$panel = $builder->addDefinition($this->prefix('panel'))
				->setFactory(AuthorizatorPanel::class)
				->setAutowired(false);

			$this->panel = $panel->getName();
		}
	}


	public function beforeCompile(): void
	{
		$builder = $this->getContainerBuilder();
		$config = $this->getConfig();
		assert($config instanceof stdClass);

		$tempDir = $builder->parameters['tempDir'] ?? sys_get_temp_dir();
		$directory = $config->enumDir ?? (is_string($tempDir) ? $tempDir : sys_get_temp_dir()).'/cache/JuniWalk.Security.Roles';
		$sources = $this->sources;
		$generator = new RoleEnumGenerator;

		foreach ($sources as $index => $source) {
			$enum = $this->enums[$index] ?? null;

			if ($enum === false) {
				continue;
			}

			$resolved = $this->resolveProvider($source, required: $enum !== null);

			if (!$resolved) {
				continue;
			}

			[$provider, $source] = $resolved;
			$name = is_string($enum) ? $enum : $provider->getEnumName();

			if ($name === null && $enum === true) {
				throw new InvalidStateException("Provider '".$provider::class."' does not name its enum, set 'enum' of the source to a name.");
			}

			if ($name === null) {
				continue;
			}

			$class = str_contains($name, '\\') ? ltrim($name, '\\') : $config->enumNamespace.'\\'.$name;

			if (isset($this->enumProviders[$class])) {
				throw new InvalidStateException("Enum '$class' is generated by more than one source of '{$this->name}'.");
			}

			$generator->write($class, $directory, $provider->load());
			$this->enumProviders[$class] = [$source, $directory];
		}
	}


	public function afterCompile(ClassType $class): void
	{
		$initialize = $class->getMethod('initialize');

		if ($this->panel !== null) {
			$initialize->addBody('$this->getService(?)->addPanel($this->getService(?), ?);', ['tracy.bar', $this->prefix('panel'), 'juniwalk.security']);
		}

		foreach ($this->enumProviders as $enum => [$source, $directory]) {
			assert(is_string($source->getEntity()));
			$initialize->addBody('\\'.RoleEnumGenerator::class.'::load(?, ?, new \\'.$source->getEntity().'(...?));', [$enum, $directory, $source->arguments]);
		}
	}


	/**
	 * Provider is instantiated at compile time and again whenever the generated file is missing,
	 * so it must be a class with constant arguments.
	 *
	 * @return array{Provider, Statement}|null null when it cannot be built and is not required
	 */
	private function resolveProvider(Statement|Reference $source, bool $required): ?array
	{
		$builder = $this->getContainerBuilder();

		if ($source instanceof Reference) {
			$definition = $builder->getDefinition((string) $source->getValue());
			$source = $definition instanceof ServiceDefinition ? $definition->getFactory() : null;
		}

		$entity = $source?->getEntity();

		if (!$source || !is_string($entity) || !class_exists($entity) || !is_a($entity, Provider::class, true)) {
			return $required ? throw new InvalidStateException("Option '{$this->name}.sources' needs a provider class with constant arguments to generate its enum.") : null;
		}

		foreach ($source->arguments as $argument) {
			if ($argument instanceof Statement || $argument instanceof Reference) {
				return $required ? throw new InvalidStateException("Provider '$entity' has service arguments, its enum cannot be generated at compile time.") : null;
			}
		}

		$provider = new $entity(...$source->arguments);

		if ($provider instanceof FileProvider) {
			$builder->addDependency($provider->getFile());
		}

		return [$provider, $source];
	}
}
