<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Attribute;

/**
 * Marks a controller method or class as publicly accessible — no valid session
 * required. Unauthenticated requests are allowed through; `zitadel.claims` will
 * be null in the handler.
 *
 * Apply to a single action method or to an entire controller class:
 * ```php
 * #[AllowAnonymous]
 * public function login(): Response { ... }
 *
 * #[AllowAnonymous]               // all actions in this class are public
 * class PublicController { ... }
 * ```
 *
 * Note on naming: `Public` is a PHP reserved keyword and cannot be used as a class
 * name. `AllowAnonymous` follows ASP.NET Core's well-known `[AllowAnonymous]` attribute.
 *
 * Support by framework:
 * - **Symfony** — `ZitadelListener` at `KernelEvents::CONTROLLER`; handles array callables
 *   `[$class, 'method']`, invokable strings, and class-level attributes
 * - **Laravel** — web-group middleware; `$request->route()->getControllerClass()` +
 *   `getActionMethod()` for reflection (route resolved before middleware fires).
 *   Native alternative: `->withoutMiddleware(ZitadelMiddleware::class)` on the route
 * - **CodeIgniter 4** — `service('router')->getController()` returns FQCN; reflects method
 * - **Mezzio** — PSR-15 core reads `RouteResult` request attribute (place after `RouteMiddleware`)
 * - **Yii 3** — PSR-15 core reads matched action attribute (place after `Router` middleware)
 * - **Phalcon MVC** — `ZitadelPlugin` handles `dispatch:beforeDispatch` (controller+action resolved)
 * - **Slim 4** — NOT supported; ZitadelMiddleware must run before routing to handle
 *   callback/logout; use `ignoredRoutes` instead
 * - **Phalcon Micro** — NOT supported; Micro routes are closures (no PHP attributes);
 *   use `ignoredRoutes` instead
 */
#[\Attribute(\Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD)]
final class AllowAnonymous {}
