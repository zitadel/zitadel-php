<?php

declare(strict_types=1);

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Yiisoft\Di\Container;
use Yiisoft\Di\ContainerConfig;
use Yiisoft\Router\UrlMatcherInterface;
use Zitadel\Sdk\Bridge\Yii\ZitadelMiddleware;

require_once __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->safeLoad();

$diConfig  = require __DIR__ . '/../config/web/di.php';
$container = new Container(ContainerConfig::create()->withDefinitions($diConfig));

$psr17   = new Psr17Factory();
$creator = new ServerRequestCreator($psr17, $psr17, $psr17, $psr17);
$request = $creator->fromGlobals();

/** @var UrlMatcherInterface $urlMatcher */
$urlMatcher = $container->get(UrlMatcherInterface::class);

// Terminal handler: resolves the matched route and dispatches to its action class.
//
// UrlMatcherInterface::match() is called a second time here (the bridge already called
// it once for #[AllowAnonymous] reflection). The double call is intentional — the
// bridge must not call CurrentRoute::setRouteWithArguments(), which throws on a second
// call, so route resolution for dispatch happens exclusively here.
$appHandler = new class ($urlMatcher, $psr17, $container) implements RequestHandlerInterface {
    public function __construct(
        private readonly UrlMatcherInterface $urlMatcher,
        private readonly Psr17Factory        $psr17,
        private readonly Container           $container,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $result = $this->urlMatcher->match($request);

        if (!$result->isSuccess()) {
            return $this->psr17->createResponse(404)
                ->withBody($this->psr17->createStream('Not Found'));
        }

        // Route::$middlewares (v4) / $middlewareDefinitions (v3) is private — read via reflection.
        // The property was renamed in yiisoft/router v4; try both names for cross-version compat.
        // The action class is always the last element (appended by Route::action()).
        $definitions = [];
        foreach (['middlewares', 'middlewareDefinitions'] as $propName) {
            try {
                $prop        = new \ReflectionProperty($result->route(), $propName);
                $definitions = (array) $prop->getValue($result->route());
                break;
            } catch (\ReflectionException) {
                // try next property name
            }
        }
        $actionClass = end($definitions);

        /** @var callable $action */
        $action = $this->container->get($actionClass);

        return $action($request, $this->psr17->createResponse());
    }
};

/** @var ZitadelMiddleware $zitadel */
$zitadel  = $container->get(ZitadelMiddleware::class);
$response = $zitadel->process($request, $appHandler);

http_response_code($response->getStatusCode());
foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $value) {
        header("{$name}: {$value}", false);
    }
}
echo $response->getBody();
