<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Tests\Files;

use JuniWalk\Security\Definitions;
use JuniWalk\Security\Provider;

final class TestProvider implements Provider
{
	public function __construct(
		private readonly Definitions $definitions,
	) {
	}


	public function getEnumName(): ?string
	{
		return null;
	}


	public function load(): Definitions
	{
		return $this->definitions;
	}
}
