<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Google\Auth\HttpHandler\HttpHandlerFactory;
use Google\Cloud\Kms\V1\KeyManagementServiceClient;
use GuzzleHttp\BodySummarizer;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Throwable;

class GkmsClientFactory
{
    public const TIMEOUT = 120;
    public const CONNECT_TIMEOUT = 10;

    public function createClient(EncryptorOptions $encryptorOptions): KeyManagementServiceClient
    {
        /* It seems that KeyManagementServiceClient client does not accept retrySettings configuration
            (as some other GCP clients do), therefore we disable retries completely and rely on application level
            retries in GenericGKMWrapper. */
        try {
            // Create the handler with passed http client with timeout settings
            $handler = HttpHandlerFactory::build($this->createHttpClient());

            // GKM client checks for authorization when created, authorization is cached in memory
            return new KeyManagementServiceClient(
                [
                    'disableRetries' => true,
                    'transportConfig' => [
                        'rest' => [
                            'httpHandler' => [$handler, 'async'],
                        ],
                    ],
                ]
            );
        } catch (Throwable $e) {
            throw new ApplicationException('Cipher key settings are invalid: ' . $e->getMessage(), 0, $e);
        }
    }

    private function createHttpClient(): Client
    {
        // copied from HttpHandlerFactory::build()
        $stack = null;
        if (class_exists(BodySummarizer::class)) {
            // double the # of characters before truncation by default
            $bodySummarizer = new BodySummarizer(240);
            $stack = HandlerStack::create();
            $stack->remove('http_errors');
            $stack->unshift(Middleware::httpErrors($bodySummarizer), 'http_errors');
        }

        return new Client([
            'timeout' => self::TIMEOUT,
            'connect_timeout' => self::CONNECT_TIMEOUT,
            'handler' => $stack,
        ]);
    }
}
