<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security;

/**
 * Null resource means all resources, null privilege means all privileges.
 */
final readonly class Rule
{
	public function __construct(
		public string $role,
		public bool $allowed = true,
		public ?string $resource = null,
		public ?string $privilege = null,
	) {
	}
}
