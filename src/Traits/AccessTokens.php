<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security\Traits;

use JuniWalk\Security\Interfaces\TokenProvider;	// ! Used for @phpstan
use JuniWalk\Security\Exceptions\PermissionDeniedException;
use Nette\Application\LinkGenerator;
use Nette\Application\UI\Link;
use Nette\Application\UI\InvalidLinkException;
use Nette\Caching\Cache;
use Nette\Caching\Storage;
use Nette\Security\IIdentity as Identity;
use Ramsey\Uuid\Uuid;
use Stringable;
use TypeError;

use function array_key_exists;
use function gettype;
use function is_array;
use function is_null;
use function is_resource;
use function is_scalar;
use function is_string;
use function ltrim;

/**
 * @phpstan-require-implements TokenProvider
 * @phpstan-import-type TokenArgs from TokenProvider
 */
trait AccessTokens
{
	private LinkGenerator $linkGenerator;
	private Cache $cache;


	public function injectAccessTokens(
		Storage $storage,
		LinkGenerator $linkGenerator,
	): void {
		$this->cache = new Cache($storage, 'Authorization.Tokens');
		$this->linkGenerator = $linkGenerator;
	}


	/**
	 * @throws PermissionDeniedException
	 */
	public function validateToken(string $token, bool $throw = true): bool
	{
		if ($token === $this->getToken() && $this->getPackage($token, false)) {
			return true;
		}

		if ($throw === false) {
			return false;
		}

		throw PermissionDeniedException::operationNotAllowed();
	}


	/**
	 * @param  TokenArgs $args
	 * @throws InvalidLinkException
	 */
	public function createToken(string|Link $dest, array $args = [], ?Identity $identity = null, string $lifespan = '20 minutes'): string
	{
		$token = (string) Uuid::uuid4();

		if ($dest instanceof Link) {
			$args = $dest->getParameters();		// ? Merge with incoming args?
			$dest = $dest->getDestination();
		}

		$dest = ltrim($dest, '/');
		$args['token'] = $token;

		if ($identity instanceof Identity) {
			$args['_identity'] = (string) $identity->getId();
		}

		$request = $this->linkGenerator->createRequest($this, $dest, $args, 'link');

		$this->cache->save($token, $request->toArray(), [
			Cache::Expire => $lifespan,
		]);

		return $token;
	}


	public function getToken(): ?string
	{
		$token = $this->getParameter('token') ?? null;

		if (!is_string($token) || !Uuid::isValid($token)) {
			return null;
		}

		return $token;
	}


	public function clearToken(?string $token = null): void
	{
		if (!$token ??= $this->getToken()) {
			return;
		}

		$this->cache->remove($token);
	}


	/**
	 * @return TokenArgs
	 */
	private function getPackage(string $token, bool $singleUseToken = true): array|false
	{
		/** @var TokenArgs */
		$package = $this->cache->load($token);
		$request = $this->getRequest()?->toArray();

		// ? Store identity aside so it does not interfere
		$identity = $package['_identity'] ?? null;
		unset($package['_identity']);

		// ? Check if the package coresponds to current request (presenter, action, id, etc.)
		if (!$package || !$this->matchesTokenRequest($package, $request ?? [])) {
			return false;
		}

		if ($singleUseToken) {
			$this->clearToken($token);
		}

		$package['_identity'] = $identity;
		return $package;
	}


	/**
	 * Checks that every cached parameter exists and matches in the current request.
	 *
	 * @param  TokenArgs $package
	 * @param  TokenArgs $request
	 * @throws TypeError if any value cannot be casted to string.
	 */
	private function matchesTokenRequest(array $package, array $request): bool
	{
		foreach ($package as $key => $value) {
			if (!array_key_exists($key, $request)) {
				return false;
			}

			$current = $request[$key];

			if (is_array($value)) {
				if (!is_array($current) || !$this->matchesTokenRequest($value, $current)) {
					return false;
				}

				continue;
			}

			if ($this->castTokenValue($value) !== $this->castTokenValue($current)) {
				return false;
			}
		}

		return true;
	}


	/**
	 * @throws TypeError if the value cannot be casted to string.
	 */
	private function castTokenValue(mixed $value): string
	{
		if (!is_scalar($value) && !is_null($value) && !is_resource($value) && !$value instanceof Stringable) {
			throw new TypeError('Type of '.gettype($value).' cannot be casted to string.');
		}

		return (string) $value;
	}
}
