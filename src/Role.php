<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security;

use Nette\Security\Role as NetteRole;

final readonly class Role implements NetteRole
{
	/**
	 * @param string[] $parents
	 */
	public function __construct(
		public string $name,
		public array $parents = [],
		public ?string $label = null,
		public ?string $color = null,
		public int $power = 0,
	) {
	}


	/**
	 * Translatable label, falls back to the role name.
	 */
	public function getLabel(): string
	{
		return $this->label ?? $this->name;
	}


	public function getRoleId(): string
	{
		return $this->name;
	}
}
