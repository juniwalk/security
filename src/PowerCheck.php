<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security;

/**
 * Record of a single Authorizator::isAllowedOver call.
 */
final class PowerCheck
{
	/**
	 * @param string[]             $roles
	 * @param array<string, ?int>  $powers power of each role, null when the role is unknown
	 */
	public function __construct(
		public readonly array $roles,
		public readonly ?string $resource,
		public readonly ?string $privilege,
		public readonly string $over,
		public readonly ?int $overPower,
		public readonly bool $granted,
		public readonly array $powers,
		public readonly bool $allowed,
	) {
	}
}
