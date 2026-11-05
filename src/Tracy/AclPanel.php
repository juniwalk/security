<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security\Tracy;

use JuniWalk\Security\Authorizator;
use Tracy\IBarPanel;

use function count;
use function htmlspecialchars;
use function implode;

/**
 * Tracy bar panel listing every role with its parents, power and the rules it is allowed or denied by.
 */
final class AclPanel implements IBarPanel
{
	public function __construct(
		private readonly Authorizator $authorizator,
	) {
	}


	public function getTab(): string
	{
		return '<span title="ACL"><svg viewBox="0 0 24 24" width="16" height="16" style="vertical-align:middle">'
			.'<path fill="#58a" d="M12 1 3 5v6c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V5z"/></svg> '
			.'<span class="tracy-label">ACL</span></span>';
	}


	public function getPanel(): string
	{
		$roles = $this->authorizator->getRoles();
		$rules = $this->authorizator->getRules();
		$html = '<h1>ACL: '.count($roles).' roles</h1><div class="tracy-inner"><div class="tracy-inner-container">';

		if (!$roles) {
			return $html.'<p>No roles are defined.</p></div></div>';
		}

		foreach ($roles as $name => $role) {
			$html .= '<h2>'.self::e($name).' <small>power '.$role->power
				.($role->parents ? ', inherits '.self::e(implode(', ', $role->parents)) : '').'</small></h2>';

			if (empty($rules[$name])) {
				$html .= '<p>No rules of its own.</p>';
				continue;
			}

			$html .= '<table style="width:100%"><tr><th>Result</th><th>Resource</th><th>Privilege</th></tr>';

			foreach ($rules[$name] as $resource => $privileges) {
				foreach ($privileges as $privilege => $allowed) {
					$html .= '<tr><td style="font-weight:bold;color:'.($allowed ? '#2a2' : '#c00').'">'.($allowed ? 'ALLOW' : 'DENY').'</td>'
						.'<td>'.self::e((string) ($resource ?: '*')).'</td>'
						.'<td>'.self::e((string) ($privilege ?: '*')).'</td></tr>';
				}
			}

			$html .= '</table>';
		}

		return $html.'</div></div>';
	}


	private static function e(string $value): string
	{
		return htmlspecialchars($value, ENT_QUOTES);
	}
}
