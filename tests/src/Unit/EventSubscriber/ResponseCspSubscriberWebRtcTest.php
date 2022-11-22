<?php

namespace Drupal\Tests\csp\Unit\EventSubscriber;

use Drupal\Core\Cache\CacheableMetadata;
use Drupal\Core\Render\HtmlResponse;
use Drupal\csp\EventSubscriber\ResponseCspSubscriber;
use Drupal\csp\LibraryPolicyBuilder;
use Drupal\csp\ReportingHandlerPluginManager;
use Drupal\Tests\UnitTestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

/**
 * Test formatting of WebRTC directive output.
 *
 * @coversDefaultClass \Drupal\csp\EventSubscriber\ResponseCspSubscriber
 * @group csp
 */
class ResponseCspSubscriberWebRtcTest extends UnitTestCase {

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
   * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface|\PHPUnit\Framework\MockObject\MockObject
   */
  private $eventDispatcher;

  /**
   * {@inheritdoc}
   */
  public function setUp(): void {
    parent::setUp();

    $this->response = $this->getMockBuilder(HtmlResponse::class)
      ->disableOriginalConstructor()
      ->getMock();
    $this->response->headers = $this->getMockBuilder(ResponseHeaderBag::class)
      ->disableOriginalConstructor()
      ->getMock();
    $responseCacheableMetadata = $this->getMockBuilder(CacheableMetadata::class)
      ->getMock();
    $this->response->method('getCacheableMetadata')
      ->willReturn($responseCacheableMetadata);

    /** @var \Symfony\Component\HttpKernel\Event\ResponseEvent|\PHPUnit\Framework\MockObject\MockObject $event */
    $this->event = $this->createMock(ResponseEvent::class);
    $this->event->expects($this->any())
      ->method('isMainRequest')
      ->willReturn(TRUE);
    $this->event->expects($this->any())
      ->method('getResponse')
      ->willReturn($this->response);

    $this->libraryPolicy = $this->createMock(LibraryPolicyBuilder::class);

    $this->reportingHandlerPluginManager = $this->createMock(ReportingHandlerPluginManager::class);

    $this->eventDispatcher = $this->createMock(EventDispatcher::class);
  }

  /**
   * Check that webrtc directive is formatted correctly.
   *
   * @covers ::onKernelResponse
   */
  public function testEmptyWebRtc() {
    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit\Framework\MockObject\MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'csp.settings' => [
        'report-only' => [
          'enable' => TRUE,
          'directives' => [
            'webrtc' => '',
          ],
        ],
        'enforce' => [
          'enable' => FALSE,
        ],
      ],
    ]);

    $this->libraryPolicy->expects($this->any())
      ->method('getSources')
      ->willReturn([]);

    $subscriber = new ResponseCspSubscriber(
      $configFactory,
      $this->libraryPolicy,
      $this->reportingHandlerPluginManager,
      $this->eventDispatcher
    );

    $this->response->headers->expects($this->never())
      ->method('set');

    $subscriber->onKernelResponse($this->event);
  }

  /**
   * Data provider for WebRTC config values.
   *
   * @return array[]
   *   Configuration values.
   */
  public function webRtcConfigProvider() {
    return [
      'allow' => ['allow'],
      'block' => ['block'],
    ];
  }

  /**
   * Check that webrtc directive is formatted correctly.
   *
   * @covers ::onKernelResponse
   * @dataProvider webRtcConfigProvider
   */
  public function testWebRtc($value) {
    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit\Framework\MockObject\MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'csp.settings' => [
        'report-only' => [
          'enable' => TRUE,
          'directives' => [
            'webrtc' => $value,
          ],
        ],
        'enforce' => [
          'enable' => FALSE,
        ],
      ],
    ]);

    $this->libraryPolicy->expects($this->any())
      ->method('getSources')
      ->willReturn([]);

    $subscriber = new ResponseCspSubscriber(
      $configFactory,
      $this->libraryPolicy,
      $this->reportingHandlerPluginManager,
      $this->eventDispatcher
    );

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy-Report-Only'),
        $this->equalTo("webrtc '$value'")
      );

    $subscriber->onKernelResponse($this->event);
  }

}
