<?php declare(strict_types=1);

/**
 * @copyright Martin Procházka (c) 2026
 * @license   MIT License
 */

namespace JuniWalk\Security\Exceptions;

use Contributte\Translation\Wrappers\Message;
use JuniWalk\Security\Enums\Severity;
use Nette\Application\ForbiddenRequestException;
use Stringable;

use function class_exists;

final class PermissionDeniedException extends ForbiddenRequestException
{
	private Severity $severity;

	private ?string $resource = null;
	private ?string $task = null;


	public static function prohibited(string $resource, string $task, ?self $previous = null): self
	{
		$self = new self('web.message.permission-denied', 403, $previous);
		$self->severity = Severity::Danger;
		$self->resource = $resource;
		$self->task = $task;

		return $self;
	}


	public static function operationNotAllowed(): self
	{
		$self = new self('web.message.operation-not-allowed', 403);
		$self->severity = Severity::Warning;

		return $self;
	}


	public function getSeverity(): Severity
	{
		return $this->severity;
	}


	public function getResource(): ?string
	{
		return $this->resource;
	}


	public function getTask(): ?string
	{
		return $this->task;
	}


	public function createMessage(): Stringable|string
	{
		if (!class_exists(Message::class)) {
			return $this->message;
		}

		return new Message($this->message, ...[
			'resource' => $this->resource,
			'task' => $this->task,
		]);
	}


	public function createType(): string
	{
		return $this->severity->value;
	}
}
