<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security\Interfaces;

use Nette\Application\IPresenter;
use Nette\Application\UI\Link;
use Nette\Security\IIdentity as Identity;

/**
 * @phpstan-type TokenArgs array<string, mixed>
 */
interface TokenProvider extends IPresenter
{
	/**
	 * @param TokenArgs $args
	 */
	public function createToken(string|Link $dest, array $args = [], ?Identity $identity = null, string $lifespan = '20 minutes'): string;
	public function validateToken(string $token, bool $throw = true): bool;
	public function getToken(): ?string;
	public function clearToken(?string $token = null): void;
}
