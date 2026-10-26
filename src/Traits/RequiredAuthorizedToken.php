<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security\Traits;

use JuniWalk\Security\Attributes\AllowTokenAuthorization;
use Nette\Application\IPresenter;	// ! Used for @phpstan
use Nette\Application\UI\ComponentReflection;
use Nette\Application\UI\Presenter;
use Nette\Security\SimpleIdentity;
use ReflectionClass;
use ReflectionMethod;

use function array_merge;

/**
 * @phpstan-require-implements IPresenter
 */
trait RequiredAuthorizedToken
{
	use RequiredAuthorized;
	use AccessTokens;


	/**
	 * @param ReflectionClass<Presenter> $element
	 */
	public function checkRequirements(ReflectionClass|ReflectionMethod $element): void
	{
		parent::checkRequirements($element);

		$attribute = $this->findAuthorizationAttribute();

		if (!$attribute || !$token = $this->getToken()) {
			return;
		}

		if (!$package = $this->getPackage($token, $attribute->singleUseToken)) {
			return;
		}

		$user = $this->getUser();

		if ($userId = $package['_identity'] ?? null) {
			$user->login(new SimpleIdentity($userId));
			$user->refreshStorage();

			if (!$attribute->leaveAuthorized) {
				// ? Only allow identity access through token to this page
				$this->onShutdown[] = static fn() => $user->logout();
			}
		}

		$this->_isRequiredAuthorized = false;
	}


	private function findAuthorizationAttribute(): ?AllowTokenAuthorization
	{
		$action = static::formatActionMethod($this->getAction());
		$class = new ComponentReflection(static::class);

		$attributes = $class->getAttributes(AllowTokenAuthorization::class);

		if ($class->hasMethod($action)) {
			$method = $class->getMethod($action);
			$attributes = array_merge(
				$method->getAttributes(AllowTokenAuthorization::class),
				$attributes,
			);
		}

		if (empty($attributes)) {
			return null;
		}

		return $attributes[0]->newInstance();
	}
}
