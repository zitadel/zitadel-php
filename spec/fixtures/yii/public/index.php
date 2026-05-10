<?php

declare(strict_types=1);

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Yiisoft\Di\Container;
use Yiisoft\Di\ContainerConfig;
use Zitadel\Sdk\Middleware\ZitadelMiddleware;

require_once __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->safeLoad();

$diConfig  = require __DIR__ . '/../config/web/di.php';
$container = new Container(ContainerConfig::create()->withDefinitions($diConfig));

$psr17   = new Psr17Factory();
$creator = new ServerRequestCreator($psr17, $psr17, $psr17, $psr17);
$request = $creator->fromGlobals();

$path = '/' . ltrim((string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH), '/');

$appHandler = new class ($path, $psr17) implements RequestHandlerInterface {
    public function __construct(
        private readonly string       $path,
        private readonly Psr17Factory $psr17,
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($this->path === '/dashboard') {
            $claims = $request->getAttribute('zitadel.claims');
            return $this->psr17->createResponse(200)
                ->withHeader('Content-Type', 'text/plain')
                ->withBody($this->psr17->createStream("Hello {$claims?->name}"));
        }

        if ($this->path === '/health') {
            return $this->psr17->createResponse(200)
                ->withHeader('Content-Type', 'text/plain')
                ->withBody($this->psr17->createStream('OK'));
        }

        return $this->psr17->createResponse(404)
            ->withBody($this->psr17->createStream('Not Found'));
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
