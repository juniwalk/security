<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security\Providers;

use InvalidArgumentException;
use JuniWalk\Security\Definitions;
use JuniWalk\Security\Provider;
use JuniWalk\Security\Resource;
use JuniWalk\Security\Role;
use JuniWalk\Security\Rule;
use Nette\Neon\Neon;
use Nette\Utils\Json;

use function array_diff;
use function array_diff_key;
use function array_is_list;
use function array_keys;
use function array_map;
use function array_push;
use function array_values;
use function file_get_contents;
use function get_debug_type;
use function implode;
use function is_array;
use function is_file;
use function is_int;
use function is_numeric;
use function is_scalar;
use function pathinfo;
use function strtolower;

/**
 * Loads ACL definitions from .neon, .json or .php (returning array) file.
 *
 * @see ../../docs/rules.example.neon Structure of the file
 */
final class FileProvider implements Provider
{
	private const AllResources = '*';

	public function __construct(
		private readonly string $file,
	) {
	}


	public function load(): Definitions
	{
		if (!is_file($this->file)) {
			throw new InvalidArgumentException('ACL file "'.$this->file.'" does not exist.');
		}

		$type = strtolower(pathinfo($this->file, PATHINFO_EXTENSION));
		$data = (array) match ($type) {
			'neon'	=> Neon::decodeFile($this->file),
			'json'	=> Json::decode(file_get_contents($this->file) ?: '', true),
			'php'	=> require $this->file,
			default	=> throw new InvalidArgumentException('Unsupported ACL file type "'.$type.'" for file "'.$this->file.'".'),
		};

		// todo: add data validation before creating definitions using nette/schema

		if ($unknown = array_diff(array_keys($data), ['roles', 'resources', 'rules'])) {
			throw new InvalidArgumentException('ACL file contains unknown section "'.implode('", "', $unknown).'".');
		}

		return new Definitions(
			$this->roles((array) ($data['roles'] ?? [])),
			$this->resources((array) ($data['resources'] ?? [])),
			$this->rules((array) ($data['rules'] ?? [])),
		);
	}


	/**
	 * @param array<mixed> $roles
	 * @return Role[]
	 */
	private function roles(array $roles): array
	{
		$list = [];

		foreach ($roles as $name => $definition) {
			$options = [];

			if (is_array($definition) && !array_is_list($definition)) {
				$options = $definition;
				$definition = $options['parents'] ?? [];
			}

			$parents = array_map($this->toString(...), (array) $definition);
			$label = isset($options['label']) ? $this->toString($options['label']) : null;
			$color = isset($options['color']) ? $this->toString($options['color']) : null;
			$power = isset($options['power']) && is_numeric($options['power']) ? (int) $options['power'] : 0;
			$list[] = new Role($this->toString($name), $parents, $label, $color, $power);
		}

		return $list;
	}


	/**
	 * @param array<mixed> $resources
	 * @return Resource[]
	 */
	private function resources(array $resources, ?string $parent = null): array
	{
		$list = [];

		foreach ($resources as $name => $definition) {
			$children = [];
			$privileges = [];

			if (is_array($definition) && !array_is_list($definition)) {
				$privileges = (array) ($definition['privileges'] ?? []);
				$children = array_diff_key($definition, ['privileges' => true]);
			} else {
				$privileges = (array) $definition;
			}

			$list[] = new Resource($this->toString($name), $parent, array_map($this->toString(...), array_values($privileges)));
			array_push($list, ...$this->resources($children, $this->toString($name)));
		}

		return $list;
	}


	/**
	 * Accepts either the structured form (allow / deny sections) or a plain list of rules.
	 * @param array<mixed> $rules
	 * @return Rule[]
	 */
	private function rules(array $rules): array
	{
		if (array_is_list($rules)) {
			return $this->ruleList($rules);
		}

		if ($unknown = array_diff(array_keys($rules), ['allow', 'deny'])) {
			throw new InvalidArgumentException('ACL rules contain unknown section "'.implode('", "', $unknown).'", expected "allow" and "deny".');
		}

		// Deny is applied last, so it always wins over allow of the same scope
		return [
			...$this->ruleSection((array) ($rules['allow'] ?? []), true),
			...$this->ruleSection((array) ($rules['deny'] ?? []), false),
		];
	}


	/**
	 * @param array<mixed> $roles role => resource => privileges
	 * @return Rule[]
	 */
	private function ruleSection(array $roles, bool $allowed): array
	{
		$list = [];

		foreach ($roles as $role => $resources) {
			foreach ((array) $resources as $resource => $privileges) {
				if (is_int($resource)) {
					[$resource, $privileges] = [$privileges, null];
				}

				$resource = $resource === self::AllResources ? null : $this->toString($resource);

				foreach ((array) $privileges ?: [null] as $privilege) {
					$list[] = new Rule($this->toString($role), $allowed, $resource, $privilege === null ? null : $this->toString($privilege));
				}
			}
		}

		return $list;
	}


	/**
	 * @param array<mixed> $rules
	 * @return Rule[]
	 */
	private function ruleList(array $rules): array
	{
		$list = [];

		foreach ($rules as $rule) {
			if (!is_array($rule) || !isset($rule['role'])) {
				throw new InvalidArgumentException('ACL rule is missing "role".');
			}

			$privileges = (array) ($rule['privileges'] ?? $rule['privilege'] ?? [null]);

			foreach ($privileges ?: [null] as $privilege) {
				$list[] = new Rule(
					$this->toString($rule['role']),
					(bool) ($rule['allowed'] ?? true),
					isset($rule['resource']) ? $this->toString($rule['resource']) : null,
					$privilege === null ? null : $this->toString($privilege),
				);
			}
		}

		return $list;
	}


	private function toString(mixed $value): string
	{
		return is_scalar($value) ? (string) $value : throw new InvalidArgumentException('ACL definition expects a scalar value, '.get_debug_type($value).' given.');
	}
}
