<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security;

use InvalidArgumentException;
use Nette\Security\Authorizator as NetteAuthorizator;
use Nette\Security\Resource as NetteResource;
use Nette\Security\Role as NetteRole;

use function array_key_exists;
use function array_push;
use function array_shift;
use function in_array;
use function str_starts_with;
use function strrpos;
use function substr;

/**
 * Resolution order of the check: resource (specific to parents to all), then privilege
 * (view.edit to view to all), then role (itself to parents). Anything not allowed is denied.
 */
class Authorizator implements NetteAuthorizator
{
	private const NoScope = '';

	/** @var array<string, Role> */
	private array $roles = [];

	/** @var array<string, ?string> */
	private array $resources = [];

	/** @var array<string, array<string, array<string, bool>>> role => resource => privilege => allowed */
	private array $rules = [];


	public function __construct(Provider $provider)
	{
		$definitions = $provider->load();

		foreach ($definitions->roles as $role) {
			$this->roles[$role->name] = $role;
		}

		foreach ($definitions->resources as $resource) {
			$this->resources[$resource->name] = $resource->parent;
		}

		$this->validateParents();

		foreach ($definitions->rules as $rule) {
			$this->createRule($rule, $definitions->resources);
		}
	}


	public function isAllowed(NetteRole|string|null $role, NetteResource|string|null $resource, ?string $privilege): bool
	{
		$role = $role instanceof NetteRole ? $role->getRoleId() : $role;
		$resource = $resource instanceof NetteResource ? $resource->getResourceId() : $resource;

		if ($role === null) {
			return false;
		}

		$roles = $this->getRoleChain($role);

		foreach ($this->getResourceChain($resource) as $resourceId) {
			foreach (self::getPrivilegeChain($privilege) as $privilegeId) {
				foreach ($roles as $roleId) {
					if (isset($this->rules[$roleId][$resourceId][$privilegeId])) {
						return $this->rules[$roleId][$resourceId][$privilegeId];
					}
				}
			}
		}

		return false;
	}


	/**
	 * @throws InvalidArgumentException if the role does not exist
	 */
	public function getRole(Role|string $role): Role
	{
		if ($role instanceof Role) {
			$role = $role->name;
		}

		if (!isset($this->roles[$role])) {
			throw new InvalidArgumentException('Unknown role "'.$role.'".');
		}

		return $this->roles[$role];
	}


	/**
	 * @return array<string, Role> roles indexed by name in the order they were defined
	 */
	public function getRoles(): array
	{
		return $this->roles;
	}


	/**
	 * Role has power over another when its power level is equal or higher, parents are not considered.
	 */
	public function hasPowerOver(NetteRole|string $role, NetteRole|string $over): bool
	{
		$role = $role instanceof NetteRole ? $role->getRoleId() : $role;
		$over = $over instanceof NetteRole ? $over->getRoleId() : $over;

		if (!isset($this->roles[$role], $this->roles[$over])) {
			return false;
		}

		return $this->roles[$role]->power >= $this->roles[$over]->power;
	}


	/**
	 * @return string[] Role followed by all of its ancestors
	 */
	private function getRoleChain(string $role): array
	{
		$chain = [];
		$queue = [$role];

		while ($queue) {
			$current = array_shift($queue);

			if (in_array($current, $chain, true)) {
				continue;
			}

			$chain[] = $current;
			array_push($queue, ...(isset($this->roles[$current]) ? $this->roles[$current]->parents : []));
		}

		return $chain;
	}


	/**
	 * @return string[]
	 */
	private function getResourceChain(?string $resource): array
	{
		$chain = [];

		for ($node = $resource; $node !== null && !in_array($node, $chain, true); $node = $this->resources[$node] ?? null) {
			$chain[] = $node;
		}

		return [...$chain, self::NoScope];
	}


	/**
	 * @return string[] Privilege "view.edit" gives "view.edit", "view" and all privileges
	 */
	private static function getPrivilegeChain(?string $privilege): array
	{
		$chain = [];

		while ($privilege !== null && $privilege !== '') {
			$chain[] = $privilege;
			$pos = strrpos($privilege, '.');
			$privilege = $pos === false ? null : substr($privilege, 0, $pos);
		}

		return [...$chain, self::NoScope];
	}


	/**
	 * @param Resource[] $resources
	 */
	private function createRule(Rule $rule, array $resources): void
	{
		if (!isset($this->roles[$rule->role])) {
			throw new InvalidArgumentException('ACL rule uses unknown role "'.$rule->role.'".');
		}

		if ($rule->resource !== null && !array_key_exists($rule->resource, $this->resources)) {
			throw new InvalidArgumentException('ACL rule uses unknown resource "'.$rule->resource.'".');
		}

		if ($rule->privilege !== null) {
			$this->validatePrivilege($rule->privilege, $rule->resource, $resources);
		}

		$resource = $rule->resource ?? self::NoScope;
		$privilege = $rule->privilege ?? self::NoScope;

		// Broader rule replaces the narrower ones of the same role, so the later rule always wins
		if ($privilege === self::NoScope) {
			unset($this->rules[$rule->role][$resource]);
		}

		if ($resource === self::NoScope && $privilege === self::NoScope) {
			unset($this->rules[$rule->role]);
		}

		$this->rules[$rule->role][$resource][$privilege] = $rule->allowed;
	}


	private function validateParents(): void
	{
		foreach ($this->roles as $name => $role) {
			foreach ($role->parents as $parent) {
				if (!isset($this->roles[$parent])) {
					throw new InvalidArgumentException('Parent role "'.$parent.'" of "'.$name.'" is not defined.');
				}
			}
		}

		foreach ($this->resources as $name => $parent) {
			if ($parent !== null && !array_key_exists($parent, $this->resources)) {
				throw new InvalidArgumentException('Parent resource "'.$parent.'" of "'.$name.'" is not defined.');
			}
		}
	}


	/**
	 * Privileges are only validated when the resource (or its relatives) declare some.
	 *
	 * @param Resource[] $resources
	 */
	private function validatePrivilege(string $privilege, ?string $resource, array $resources): void
	{
		$pool = [];

		foreach ($resources as $definition) {
			$related = $resource === null
				|| in_array($resource, $this->getResourceChain($definition->name), true)
				|| in_array($definition->name, $this->getResourceChain($resource), true);

			if ($related) {
				array_push($pool, ...$definition->privileges);
			}
		}

		foreach ($pool as $declared) {
			if ($declared === $privilege || str_starts_with($declared, $privilege.'.')) {
				return;
			}
		}

		if ($pool) {
			throw new InvalidArgumentException('Privilege "'.$privilege.'" is not defined for resource "'.($resource ?? '*').'".');
		}
	}
}
