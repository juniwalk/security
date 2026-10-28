<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security;

interface Provider
{
	public function load(): Definitions;

	/**
	 * Name for the generated role enum, null when the provider cannot tell.
	 */
	public function getEnumName(): ?string;
}
