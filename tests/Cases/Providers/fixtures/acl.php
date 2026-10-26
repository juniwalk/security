<?php declare(strict_types=1);

return [
	'roles' => [
		'guest' => []
	],

	'resources' => [
		'Article' => ['view']
	],

	'rules' => [
		['role' => 'guest', 'resource' => 'Article']
	]
];
