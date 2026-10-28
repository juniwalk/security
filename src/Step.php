<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security;

/**
 * Single lookup of a rule, null rule means nothing was defined for the combination.
 */
final class Step
{
	public function __construct(
		public readonly string $role,
		public readonly string $resource,
		public readonly string $privilege,
		public readonly ?bool $rule,
	) {
	}
}
