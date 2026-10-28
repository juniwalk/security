<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security\Tracy;

use JuniWalk\Security\Authorizator;
use JuniWalk\Security\Check;
use Tracy\IBarPanel;

use function array_map;
use function count;
use function htmlspecialchars;
use function implode;

/**
 * Tracy bar panel listing every Authorizator::isAllowed call with the path it took to the result.
 */
final class AuthorizatorPanel implements IBarPanel
{
	/** @var Check[] */
	private array $checks = [];


	public function __construct(Authorizator $authorizator)
	{
		$authorizator->onCheck[] = function(Check $check): void {
			$this->checks[] = $check;
		};
	}


	public function getTab(): string
	{
		$denied = 0;

		foreach ($this->checks as $check) {
			$denied += $check->allowed ? 0 : 1;
		}

		$color = $denied ? '#c00' : '#2a2';

		return '<span title="Authorizator"><svg viewBox="0 0 24 24" width="16" height="16" style="vertical-align:middle">'
			.'<path fill="'.$color.'" d="M12 1 3 5v6c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V5z"/></svg> '
			.'<span class="tracy-label">'.count($this->checks).($denied ? ' / '.$denied.' denied' : '').'</span></span>';
	}


	public function getPanel(): string
	{
		$html = '<h1>Authorizator: '.count($this->checks).' checks</h1><div class="tracy-inner"><div class="tracy-inner-container">';

		if (!$this->checks) {
			return $html.'<p>No isAllowed checks were made.</p></div></div>';
		}

		$html .= '<table style="width:100%"><tr><th>#</th><th>Result</th><th>Role</th><th>Resource</th><th>Privilege</th><th>Path</th></tr>';

		foreach ($this->checks as $index => $check) {
			$html .= '<tr><td>'.($index + 1).'</td>'
				.'<td style="font-weight:bold;color:'.($check->allowed ? '#2a2' : '#c00').'">'.($check->allowed ? 'ALLOW' : 'DENY').'</td>'
				.'<td>'.self::e($check->role).'</td>'
				.'<td>'.self::e($check->resource ?? '*').'</td>'
				.'<td>'.self::e($check->privilege ?? '*').'</td>'
				.'<td>'.$this->renderPath($check).'</td></tr>';
		}

		return $html.'</table></div></div>';
	}


	private function renderPath(Check $check): string
	{
		$html = '<small>roles: '.self::chain($check->roleChain)
			.'<br>resources: '.self::chain($check->resourceChain)
			.'<br>privileges: '.self::chain($check->privilegeChain).'</small>'
			.'<ol style="margin:4px 0">';

		foreach ($check->steps as $step) {
			$what = 'role <b>'.self::e($step->role).'</b>, resource <b>'.self::e($step->resource ?: '*').'</b>, privilege <b>'.self::e($step->privilege ?: '*').'</b>';
			$html .= '<li>'.$what.' → '.match ($step->rule) {
				true => '<b style="color:#2a2">allowed</b> (decisive)',
				false => '<b style="color:#c00">denied</b> (decisive)',
				null => 'no rule',
			}.'</li>';
		}

		if (!$check->getDecisive()) {
			$html .= '<li><b style="color:#c00">no rule matched, denied by default</b></li>';
		}

		return $html.'</ol>';
	}


	/**
	 * @param string[] $chain
	 */
	private static function chain(array $chain): string
	{
		return self::e(implode(' → ', array_map(fn($item) => $item ?: '*', $chain)));
	}


	private static function e(string $value): string
	{
		return htmlspecialchars($value, ENT_QUOTES);
	}
}
