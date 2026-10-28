<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security;

use function array_key_last;

/**
 * Record of a single Authorizator::isAllowed call and the path it took.
 */
final class Check
{
	/**
	 * @param string[] $roleChain
	 * @param string[] $resourceChain
	 * @param string[] $privilegeChain
	 * @param Step[]   $steps
	 */
	public function __construct(
		public readonly string $role,
		public readonly ?string $resource,
		public readonly ?string $privilege,
		public readonly bool $allowed,
		public readonly array $roleChain,
		public readonly array $resourceChain,
		public readonly array $privilegeChain,
		public readonly array $steps,
	) {
	}


	public function getDecisive(): ?Step
	{
		$last = $this->steps ? $this->steps[array_key_last($this->steps)] : null;

		return $last?->rule !== null ? $last : null;
	}
}
