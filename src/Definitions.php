<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security;

final readonly class Definitions
{
	/**
	 * @param Role[] $roles
	 * @param Resource[] $resources
	 * @param Rule[] $rules
	 */
	public function __construct(
		public array $roles = [],
		public array $resources = [],
		public array $rules = [],
	) {
	}
}
