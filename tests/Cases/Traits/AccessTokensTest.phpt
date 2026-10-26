<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Tests\Cases\Traits;

require __DIR__.'/../../bootstrap.php';

use JuniWalk\Security\Interfaces\TokenProvider;
use JuniWalk\Security\Traits\AccessTokens;
use Nette\Application\UI\Presenter;
use ReflectionMethod;
use Tester\Assert;
use Tester\TestCase;

/**
 * @testCase
 */
final class AccessTokensTest extends TestCase
{
	public function testRequestMatching(): void
	{
		Assert::true($this->matches(
			['id' => 1, 'filters' => ['status' => 'active']],
			['id' => '1', 'filters' => ['status' => 'active', 'page' => 2], 'extra' => true],
		));
	}


	public function testRequestMismatch(): void
	{
		Assert::false($this->matches(['filters' => ['status' => 'active']], ['filters' => ['status' => 'inactive']]));
		Assert::false($this->matches(['filters' => ['status' => 'active']], ['filters' => 'active']));
		Assert::false($this->matches(['id' => null], []));
		Assert::true($this->matches(['id' => null], ['id' => '']));
	}


	private function matches(array $package, array $request): bool
	{
		$presenter = new class extends Presenter implements TokenProvider {
			use AccessTokens;
		};

		$method = new ReflectionMethod($presenter, 'matchesTokenRequest');
		return $method->invoke($presenter, $package, $request);
	}
}

(new AccessTokensTest)->run();
