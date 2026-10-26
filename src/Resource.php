<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security;

final readonly class Resource
{
	/**
	 * @param string[] $privileges Privileges that can be granted on this resource
	 */
	public function __construct(
		public string $name,
		public ?string $parent = null,
		public array $privileges = [],
	) {
	}
}
