<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Yii;

use Psr\Http\Message\ResponseFactoryInterface;
use Yiisoft\Di\Container;
use Yiisoft\Yii\Web\Application;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Middleware\ZitadelMiddleware;

/**
 * Yii 3 bootstrap that registers the Zitadel DI bindings.
 *
 * Add to `config/web/di.php`:
 * ```php
 * ZitadelConfig::class => [
 *     '__class' => ZitadelConfig::class,
 *     '__construct()' => [
 *         'issuerUrl'    => $_ENV['ZITADEL_ISSUER_URL'],
 *         'clientId'     => $_ENV['ZITADEL_CLIENT_ID'],
 *         'redirectUri'  => $_ENV['ZITADEL_REDIRECT_URI'],
 *         'cookieSecret' => $_ENV['ZITADEL_COOKIE_SECRET'],
 *         'protectAll'   => true,
 *     ],
 * ],
 * JwksCache::class => ['__class' => JwksCache::class],
 * TokenValidator::class => ['__class' => TokenValidator::class],
 * ZitadelMiddleware::class => ['__class' => ZitadelMiddleware::class],
 * ```
 *
 * Add to `config/web/application.php` middleware pipeline before `Router::class`:
 * ```php
 * MiddlewareDispatcher::class => [
 *     '__class' => MiddlewareDispatcher::class,
 *     'addMiddleware()' => [ZitadelMiddleware::class],
 * ],
 * ```
 *
 * Access claims in action handlers:
 * ```php
 * $claims = $request->getAttribute('zitadel.claims');
 * ```
 *
 * See `docs/yii.md` for the full setup guide.
 */
readonly class ZitadelBootstrap
{
    public function __construct(
        private ZitadelConfig            $config,
        private TokenValidator           $validator,
        private ResponseFactoryInterface $responseFactory,
    ) {}

    /**
     * Returns the configured {@see ZitadelMiddleware} for direct use in the
     * Yii 3 PSR-15 pipeline. Typical usage via the DI container:
     *
     * ```php
     * $bootstrap = $container->get(ZitadelBootstrap::class);
     * $app->addMiddleware($bootstrap->middleware());
     * ```
     */
    public function middleware(): ZitadelMiddleware
    {
        return new ZitadelMiddleware($this->config, $this->validator, $this->responseFactory);
    }
}
