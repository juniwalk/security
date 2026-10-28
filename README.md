# juniwalk/security

Extended security tools for Nette. Currently provides a flexible ACL on top of `Nette\Security\Permission`.

## Setup

```neon
extensions:
	permission: JuniWalk\Security\DI\PermissionExtension

permission:
	strict: true            # duplicate role or resource across sources throws, false merges them
	sources:                # services, class names or statements implementing JuniWalk\Security\Provider
		- JuniWalk\Security\Providers\FileProvider(%appDir%/config/permission.neon)
		- @customProvider
		- source: JuniWalk\Security\Providers\FileProvider(%appDir%/config/admin.neon)
		  enum: AdminRole   # optional, overrides the name given by the provider, false disables the enum
	enumNamespace: App\Security      # default JuniWalk\Security\Roles
	enumDir: %appDir%/Security       # default %tempDir%/cache/JuniWalk.Security.Roles
```

Sources are merged in the listed order, rules keep that order too (later overrides earlier).

A provider that names its enum (`Provider::getEnumName()`, `null` means none) gets a string-backed enum with a case per role generated at container build (`AdminRole::Admin`, `label()`, `color()`, `power()`, `hasPowerOver()`, `getMap()`, implements `LabeledEnum` and `PoweredRole` from juniwalk/utils). `FileProvider` reads the name from the top level `enum` key of its file (`enum: AdminRole`, or `enum: true` for PascalCase of the file name). A name with a backslash is a full class name, otherwise it goes to `enumNamespace`. Providers are instantiated at compile time, so they must be classes with constant arguments (a source with service arguments is skipped unless `enum` is set, then it throws). Enum files are written to `enumDir` and recreated when missing, so clearing the cache is safe.

## Definitions

See [rules.example.neon](docs/rules.example.neon). Roles may have multiple parents and optionally a translatable `label` and a `color` (plain strings, exposed as `Role::getLabel()` and `Role::$color`; use the mapping form `{parents, label, color}`). Resources can be nested, a child inherits rules of its parent resource (a rule on `Menu:Web` covers every resource under it).
A list declares privileges of a resource, a resource with children uses the reserved `privileges:` key for its own. Resources declare allowed privileges
and rules are applied in order (later overrides earlier).

Rules are written in a structured form, `allow` is applied first and `deny` after it, so deny always wins:

```neon
rules:
	allow:
		guest:
			Auth:                    # no privileges means all of them
		user:
			Web:Product: [view, edit]
		admin:
			'*':                     # every resource
	deny:
		admin:
			Web:Product: [edit.approval]
```

A plain list `- {role: user, resource: Web:Product, privileges: [view], allowed: true}` is accepted too, when the order of rules matters. A rule on privilege `edit` also covers declared `edit.*` privileges.

## Role power

`Authorizator::hasPowerOver($role, $over)` compares the numeric `power` of roles (default `0`, set it in the mapping form: `power: 2`). It is separate from inheritance, equal or higher power wins. Unknown roles never have power.

## Presenters

- `JuniWalk\Security\ACL\Traits\RequiredAuthorized` checks `view.<action>` on the presenter resource.
- `JuniWalk\Security\ACL\Traits\RequiredAuthorizedToken` adds token based access via `#[AllowTokenAuthorization]`.
