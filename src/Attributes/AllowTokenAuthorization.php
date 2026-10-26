<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security\Attributes;

use Attribute;

#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
class AllowTokenAuthorization
{
	public function __construct(
		public readonly bool $singleUseToken = false,
		public readonly bool $leaveAuthorized = false,
	) {
	}
}
