<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security\Enums;

enum Severity: string
{
	case Success = 'success';
	case Danger = 'danger';
	case Warning = 'warning';
	case Info = 'info';
	case Primary = 'primary';
}
