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

use function array_push;
use function array_unique;
use function array_values;
use function max;

/**
 * Merges definitions of multiple providers, rules keep the order of providers.
 * Duplicate role or resource throws in strict mode, otherwise its parents and privileges are merged.
 */
final class CompositeProvider implements Provider
{
	/**
	 * @param Provider[] $providers
	 */
	public function __construct(
		private readonly array $providers,
		private readonly bool $strict = true,
	) {
	}


	public function load(): Definitions
	{
		$roles = $resources = $rules = [];

		foreach ($this->providers as $provider) {
			$definitions = $provider->load();

			foreach ($definitions->roles as $role) {
				$roles[$role->name] = $this->mergeRole($roles[$role->name] ?? null, $role);
			}

			foreach ($definitions->resources as $resource) {
				$resources[$resource->name] = $this->mergeResource($resources[$resource->name] ?? null, $resource);
			}

			array_push($rules, ...$definitions->rules);
		}

		return new Definitions(array_values($roles), array_values($resources), $rules);
	}


	private function mergeRole(?Role $current, Role $role): Role
	{
		if ($current === null) {
			return $role;
		}

		$this->assertMergeable('role', $role->name);

		return new Role(
			$role->name,
			array_values(array_unique([...$current->parents, ...$role->parents])),
			$role->label ?? $current->label,
			$role->color ?? $current->color,
			max($current->power, $role->power),
		);
	}


	private function mergeResource(?Resource $current, Resource $resource): Resource
	{
		if ($current === null) {
			return $resource;
		}

		$this->assertMergeable('resource', $resource->name);

		if ($current->parent !== null && $resource->parent !== null && $current->parent !== $resource->parent) {
			throw new InvalidArgumentException('Resource "'.$resource->name.'" has conflicting parents "'.$current->parent.'" and "'.$resource->parent.'".');
		}

		return new Resource(
			$resource->name,
			$current->parent ?? $resource->parent,
			array_values(array_unique([...$current->privileges, ...$resource->privileges])),
		);
	}


	private function assertMergeable(string $type, string $name): void
	{
		if ($this->strict) {
			throw new InvalidArgumentException('Duplicate '.$type.' "'.$name.'" defined by multiple ACL sources.');
		}
	}
}
