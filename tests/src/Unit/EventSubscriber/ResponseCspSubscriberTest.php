<?php

namespace Drupal\Tests\csp\Unit\EventSubscriber;

use Drupal\Core\Cache\CacheableMetadata;
use Drupal\Core\Render\HtmlResponse;
use Drupal\csp\Csp;
use Drupal\csp\CspEvents;
use Drupal\csp\Event\PolicyAlterEvent;
use Drupal\csp\EventSubscriber\ResponseCspSubscriber;
use Drupal\csp\LibraryPolicyBuilder;
use Drupal\csp\ReportingHandlerPluginManager;
use Drupal\Tests\UnitTestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * @coversDefaultClass \Drupal\csp\EventSubscriber\ResponseCspSubscriber
 * @group csp
 */
class ResponseCspSubscriberTest extends UnitTestCase {

  /**
   * Mock HTTP Response.
   *
   * @var \Drupal\Core\Render\HtmlResponse|\PHPUnit\Framework\MockObject\MockObject
   */
  protected $response;

  /**
   * Mock Response Event.
   *
   * @var \Symfony\Component\HttpKernel\Event\ResponseEvent|\PHPUnit\Framework\MockObject\MockObject
   */
  protected $event;

  /**
   * The Library Policy service.
   *
   * @var \Drupal\csp\LibraryPolicyBuilder|\PHPUnit\Framework\MockObject\MockObject
   */
  private $libraryPolicy;

  /**
   * The Reporting Handler Plugin Manager service.
   *
   * @var \Drupal\csp\ReportingHandlerPluginManager|\PHPUnit\Framework\MockObject\MockObject
   */
  private $reportingHandlerPluginManager;

  /**
   * The Event Dispatcher Service.
   *
   * @var \PHPUnit\Framework\MockObject\MockObject|\Symfony\Component\EventDispatcher\EventDispatcherInterface
   */
  private $eventDispatcher;

  /**
   * {@inheritdoc}
   */
  public function setUp(): void {
    parent::setUp();

    $this->response = $this->createMock(HtmlResponse::class);
    $this->response->headers = $this->createMock(ResponseHeaderBag::class);
    $responseCacheableMetadata = $this->createMock(CacheableMetadata::class);
    $this->response->method('getCacheableMetadata')
      ->willReturn($responseCacheableMetadata);

    $this->event = new ResponseEvent(
      $this->createMock(HttpKernelInterface::class),
      $this->createMock(Request::class),
      HttpKernelInterface::MASTER_REQUEST,
      $this->response
    );

    $this->libraryPolicy = $this->createMock(LibraryPolicyBuilder::class);

    $this->reportingHandlerPluginManager = $this->createMock(ReportingHandlerPluginManager::class);

    $this->eventDispatcher = $this->createMock(EventDispatcher::class);
  }

  /**
   * Check that the subscriber listens to the Response event.
   *
   * @covers ::getSubscribedEvents
   */
  public function testSubscribedEvents() {
    $this->assertArrayHasKey(KernelEvents::RESPONSE, ResponseCspSubscriber::getSubscribedEvents());
  }

  /**
   * Check that Policy Alter events are dispatched.
   *
   * @covers ::onKernelResponse
   */
  public function testPolicyAlterEvent() {

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit\Framework\MockObject\MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'csp.settings' => [
        'report-only' => [
          'enable' => TRUE,
          'directives' => [
            'style-src' => [
              'base' => 'any',
            ],
          ],
        ],
        'enforce' => [
          'enable' => TRUE,
          'directives' => [
            'script-src' => [
              'base' => 'self',
            ],
          ],
        ],
      ],
    ]);

    $this->eventDispatcher->expects($this->exactly(2))
      ->method('dispatch')
      ->with(
        $this->callback(function (PolicyAlterEvent $event) {
          $policy = $event->getPolicy();
          return $policy->hasDirective(($policy->isReportOnly() ? 'style-src' : 'script-src'));
        }),
        $this->equalTo(CspEvents::POLICY_ALTER)
      )
      ->willReturnCallback(function ($event, $eventName) {
        $policy = $event->getPolicy();
        $policy->setDirective('font-src', [Csp::POLICY_SELF]);
        return $event;
      });

    $this->response->headers->expects($this->exactly(2))
      ->method('set')
      ->withConsecutive(
        [
          $this->equalTo('Content-Security-Policy-Report-Only'),
          $this->equalTo("font-src 'self'; style-src *"),
        ],
        [
          $this->equalTo('Content-Security-Policy'),
          $this->equalTo("font-src 'self'; script-src 'self'"),
        ]
      );

    $subscriber = new ResponseCspSubscriber($configFactory, $this->libraryPolicy, $this->reportingHandlerPluginManager, $this->eventDispatcher);

    $subscriber->onKernelResponse($this->event);
  }

  /**
   * An empty or missing directive list should not output a header.
   *
   * @covers ::onKernelResponse
   */
  public function testEmptyDirective() {
    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit\Framework\MockObject\MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'csp.settings' => [
        'report-only' => [
          'enable' => TRUE,
          'directives' => [],
        ],
        'enforce' => [
          'enable' => TRUE,
        ],
      ],
    ]);

    $subscriber = new ResponseCspSubscriber($configFactory, $this->libraryPolicy, $this->reportingHandlerPluginManager, $this->eventDispatcher);

    $this->response->headers->expects($this->never())
      ->method('set');
    $this->response->getCacheableMetadata()
      ->expects($this->once())
      ->method('addCacheTags')
      ->with(['config:csp.settings']);

    $subscriber->onKernelResponse($this->event);
  }

  /**
   * Check the policy with enforcement enabled.
   *
   * @covers ::onKernelResponse
   */
  public function testEnforcedResponse() {

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit\Framework\MockObject\MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'csp.settings' => [
        'enforce' => [
          'enable' => TRUE,
          'directives' => [
            'script-src' => [
              'base' => 'self',
              'flags' => [
                'unsafe-inline',
              ],
            ],
            'style-src' => [
              'base' => 'self',
            ],
          ],
        ],
        'report-only' => [
          'enable' => FALSE,
        ],
      ],
    ]);

    $this->libraryPolicy->expects($this->any())
      ->method('getSources')
      ->willReturn([]);

    $subscriber = new ResponseCspSubscriber($configFactory, $this->libraryPolicy, $this->reportingHandlerPluginManager, $this->eventDispatcher);

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy'),
        $this->equalTo("script-src 'self' 'unsafe-inline'; style-src 'self'")
      );

    $subscriber->onKernelResponse($this->event);
  }

  /**
   * Check the generated headers with both policies enabled.
   *
   * @covers ::onKernelResponse
   */
  public function testBothPolicies() {

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit\Framework\MockObject\MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'csp.settings' => [
        'report-only' => [
          'enable' => TRUE,
          'directives' => [
            'script-src' => [
              'base' => 'any',
              'flags' => [
                'unsafe-inline',
              ],
            ],
            'style-src' => [
              'base' => 'any',
              'flags' => [
                'unsafe-inline',
              ],
            ],
          ],
        ],
        'enforce' => [
          'enable' => TRUE,
          'directives' => [
            'script-src' => [
              'base' => 'self',
            ],
            'style-src' => [
              'base' => 'self',
            ],
          ],
        ],
      ],
    ]);

    $this->libraryPolicy->expects($this->any())
      ->method('getSources')
      ->willReturn([]);

    $subscriber = new ResponseCspSubscriber($configFactory, $this->libraryPolicy, $this->reportingHandlerPluginManager, $this->eventDispatcher);

    $this->response->headers->expects($this->exactly(2))
      ->method('set')
      ->withConsecutive(
        [
          $this->equalTo('Content-Security-Policy-Report-Only'),
          $this->equalTo("script-src * 'unsafe-inline'; style-src * 'unsafe-inline'"),
        ],
        [
          $this->equalTo('Content-Security-Policy'),
          $this->equalTo("script-src 'self'; style-src 'self'"),
        ]
      );

    $subscriber->onKernelResponse($this->event);
  }

  /**
   * Test that library sources are included.
   *
   * @covers ::onKernelResponse
   */
  public function testWithLibraryDirective() {

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit\Framework\MockObject\MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'csp.settings' => [
        'report-only' => [
          'enable' => TRUE,
          'directives' => [
            'script-src' => [
              'base' => 'any',
              'flags' => [
                'unsafe-inline',
              ],
            ],
            'style-src' => [
              'base' => 'self',
              'flags' => [
                'unsafe-inline',
              ],
            ],
            'style-src-elem' => [
              'base' => 'self',
            ],
          ],
        ],
      ],
    ]);

    $this->libraryPolicy->expects($this->any())
      ->method('getSources')
      ->willReturn([
        'style-src' => ['example.com'],
        'style-src-elem' => ['example.com'],
      ]);

    $subscriber = new ResponseCspSubscriber($configFactory, $this->libraryPolicy, $this->reportingHandlerPluginManager, $this->eventDispatcher);

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy-Report-Only'),
        $this->equalTo("script-src * 'unsafe-inline'; style-src 'self' 'unsafe-inline' example.com; style-src-elem 'self' example.com")
      );

    $subscriber->onKernelResponse($this->event);
  }

  /**
   * Test that library sources do not override a disabled directive.
   *
   * @covers ::onKernelResponse
   */
  public function testDisabledLibraryDirective() {

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit\Framework\MockObject\MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'csp.settings' => [
        'report-only' => [
          'enable' => TRUE,
          'directives' => [
            'script-src' => [
              'base' => 'any',
              'flags' => [
                'unsafe-inline',
              ],
            ],
            'style-src' => [
              'base' => 'self',
              'flags' => [
                'unsafe-inline',
              ],
            ],
            // style-src-elem is purposefully omitted.
          ],
        ],
      ],
    ]);

    $this->libraryPolicy->expects($this->any())
      ->method('getSources')
      ->willReturn([
        'style-src' => ['example.com'],
        'style-src-elem' => ['example.com'],
      ]);

    $subscriber = new ResponseCspSubscriber($configFactory, $this->libraryPolicy, $this->reportingHandlerPluginManager, $this->eventDispatcher);

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy-Report-Only'),
        $this->equalTo("script-src * 'unsafe-inline'; style-src 'self' 'unsafe-inline' example.com")
      );

    $subscriber->onKernelResponse($this->event);
  }

}
