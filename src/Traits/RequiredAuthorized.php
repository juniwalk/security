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

		try {
			if (!$user->isAllowed($resource, $task)) {
				throw PermissionDeniedException::prohibited($resource, $task);
			}

		} catch (InvalidStateException) {
			return;
		}

		$authorizator = $user->getAuthorizatorIfExists();

		// ? Unable to check power over the role if no role is given or authorizator is not available
		if (!$role || !$authorizator instanceof Authorizator) {
			return;
		}

		foreach ($user->getRoles() as $me) {
			if (!$authorizator->hasPowerOver($me, $role)) {
				continue;
			}

			return;
		}

		// ? None of the roles of the user have power over the given role
		throw PermissionDeniedException::prohibited($resource, $task);
	}
}
