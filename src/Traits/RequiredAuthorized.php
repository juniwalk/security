<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security\Traits;

use JuniWalk\Security\Authorizator;
use JuniWalk\Security\Exceptions\PermissionDeniedException;
use Nette\Application\IPresenter;	// ! Used for @phpstan
use Nette\InvalidStateException;
use Nette\Security\Role;

/**
 * @phpstan-require-implements IPresenter
 */
trait RequiredAuthorized
{
	protected bool $_isRequiredAuthorized = true;

	public function injectRequireAuthorization(): void
	{
		$this->onStartup[] = $this->forceAuthorized(...);
	}


	/**
	 * @throws PermissionDeniedException
	 */
	private function forceAuthorized(): void
	{
		if (!$this->_isRequiredAuthorized) {
			return;
		}

		$this->isAllowed(
			resource: $this->getName(),
			task: 'view.'.$this->getAction(),
		);
	}


	/**
	 * @throws PermissionDeniedException
	 */
	public function isAllowed(?string $resource, ?string $task, Role|string|null $role = null): void
	{
		$user = $this->getUser();

		if (!$resource || !$task) {
			return;
		}

		$authorizator = $user->getAuthorizatorIfExists();

		// ? Include power checking if the role is specified and the authorizator supports it
		if ($role && $authorizator instanceof Authorizator) {
			if (!$authorizator->isAllowedOver($user->getRoles(), $resource, $task, $role)) {
				throw PermissionDeniedException::prohibited($resource, $task);
			}

			return;
		}

		try {
			if (!$user->isAllowed($resource, $task)) {
				throw PermissionDeniedException::prohibited($resource, $task);
			}

		} catch (InvalidStateException) {
			return;
		}
	}
}
