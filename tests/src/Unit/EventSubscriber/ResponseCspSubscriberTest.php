<?php

namespace Drupal\Tests\csp\Unit\EventSubscriber;

use Drupal\Core\Asset\LibraryDiscovery;
use Drupal\Core\Cache\MemoryBackend;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Render\HtmlResponse;
use Drupal\csp\EventSubscriber\ResponseCspSubscriber;
use Drupal\Tests\UnitTestCase;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * @coversDefaultClass Drupal\csp\EventSubscriber\ResponseCspSubscriber
 * @group csp
 */
class ResponseCspSubscriberTest extends UnitTestCase {

  /**
   * Mock HTTP Response.
   *
   * @var \Drupal\Core\Render\HtmlResponse|\PHPUnit_Framework_MockObject_MockObject
   */
  protected $response;

  /**
   * Mock Response Event.
   *
   * @var \Symfony\Component\HttpKernel\Event\FilterResponseEvent|\PHPUnit_Framework_MockObject_MockObject
   */
  protected $event;

  /**
   * Memory Cache backend.
   *
   * @var \Drupal\Core\Cache\CacheBackendInterface
   */
  protected $cache;

  /**
   * Mock Module Handler.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface|\PHPUnit_Framework_MockObject_MockObject
   */
  protected $moduleHandler;

  /**
   * Mock Library Discovery.
   *
   * @var \Drupal\Core\Asset\LibraryDiscoveryInterface|\PHPUnit_Framework_MockObject_MockObject
   */
  protected $libraryDiscovery;

  /**
   * {@inheritdoc}
   */
  public function setUp() {
    parent::setUp();

    $this->response = $this->getMockBuilder(HtmlResponse::class)
      ->disableOriginalConstructor()
      ->getMock();
    $this->response->headers = $this->getMockBuilder(ResponseHeaderBag::class)
      ->disableOriginalConstructor()
      ->getMock();

    /** @var \Symfony\Component\HttpKernel\Event\FilterResponseEvent|\PHPUnit_Framework_MockObject_MockObject $event */
    $this->event = $this->getMockBuilder(FilterResponseEvent::class)
      ->disableOriginalConstructor()
      ->getMock();
    $this->event->expects($this->any())
      ->method('isMasterRequest')
      ->willReturn(TRUE);
    $this->event->expects($this->any())
      ->method('getResponse')
      ->willReturn($this->response);

    $this->cache = new MemoryBackend();

    $this->moduleHandler = $this->getMockBuilder(ModuleHandler::class)
      ->disableOriginalConstructor()
      ->getMock();

    $this->libraryDiscovery = $this->getMockBuilder(LibraryDiscovery::class)
      ->disableOriginalConstructor()
      ->getMock();
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
   * Check the policy with CSS optimization disabled in Drupal <=8.5.
   *
   * @covers ::onKernelResponse
   */
  public function testUnoptimizedResponse85() {

    if (version_compare(\Drupal::VERSION, '8.6', '>=')) {
      $this->markTestSkipped("Test for drupal/core <=8.5");
    }

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit_Framework_MockObject_MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'system.performance' => [
        'css.preprocess' => FALSE,
      ],
      'csp.settings' => [
        'enforce' => FALSE,
      ],
    ]);

    $this->moduleHandler->expects($this->any())
      ->method('getModuleList')
      ->willReturn([]);

    $subscriber = new ResponseCspSubscriber($configFactory, $this->cache, $this->moduleHandler, $this->libraryDiscovery);

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy-Report-Only'),
        $this->equalTo("script-src 'self'; style-src 'self' 'unsafe-inline'")
      );

    $subscriber->onKernelResponse($this->event);
  }

  /**
   * Check the policy with CSS optimization disabled in Drupal >=8.6.
   *
   * @covers ::onKernelResponse
   */
  public function testUnoptimizedResponse86() {

    if (version_compare(\Drupal::VERSION, '8.6', '<')) {
      $this->markTestSkipped("Test for drupal/core >=8.6");
    }

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit_Framework_MockObject_MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'system.performance' => [
        'css.preprocess' => FALSE,
      ],
      'csp.settings' => [
        'enforce' => FALSE,
      ],
    ]);

    $this->moduleHandler->expects($this->any())
      ->method('getModuleList')
      ->willReturn([]);

    $subscriber = new ResponseCspSubscriber($configFactory, $this->cache, $this->moduleHandler, $this->libraryDiscovery);

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy-Report-Only'),
        $this->equalTo("script-src 'self'; style-src 'self'")
      );

    $subscriber->onKernelResponse($this->event);
  }

  /**
   * Check the policy with CSS optimization disabled if IE9 module installed.
   *
   * @covers ::onKernelResponse
   */
  public function testUnoptimizedResponseIe9() {

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit_Framework_MockObject_MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'system.performance' => [
        'css.preprocess' => FALSE,
      ],
      'csp.settings' => [
        'enforce' => FALSE,
      ],
    ]);

    $this->moduleHandler->expects($this->any())
      ->method('moduleExists')
      ->with($this->equalTo('ie9'))
      ->willReturn(TRUE);

    $this->moduleHandler->expects($this->any())
      ->method('getModuleList')
      ->willReturn([]);

    $subscriber = new ResponseCspSubscriber($configFactory, $this->cache, $this->moduleHandler, $this->libraryDiscovery);

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy-Report-Only'),
        $this->equalTo("script-src 'self'; style-src 'self' 'unsafe-inline'")
      );

    $subscriber->onKernelResponse($this->event);
  }

  /**
   * Check the policy with CSS optimization enabled.
   *
   * @covers ::onKernelResponse
   */
  public function testOptimizedResponse() {

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit_Framework_MockObject_MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'system.performance' => [
        'css.preprocess' => TRUE,
      ],
      'csp.settings' => [
        'enforce' => FALSE,
      ],
    ]);

    $this->moduleHandler->expects($this->any())
      ->method('getModuleList')
      ->willReturn([]);

    $subscriber = new ResponseCspSubscriber($configFactory, $this->cache, $this->moduleHandler, $this->libraryDiscovery);

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy-Report-Only'),
        $this->equalTo("script-src 'self'; style-src 'self'")
      );

    $subscriber->onKernelResponse($this->event);
  }

  /**
   * Check the policy with enforcement enabled.
   *
   * @covers ::onKernelResponse
   */
  public function testEnforcedResponse() {

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit_Framework_MockObject_MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'system.performance' => [
        'css.preprocess' => TRUE,
      ],
      'csp.settings' => [
        'enforce' => TRUE,
      ],
    ]);

    $this->moduleHandler->expects($this->any())
      ->method('getModuleList')
      ->willReturn([]);

    $subscriber = new ResponseCspSubscriber($configFactory, $this->cache, $this->moduleHandler, $this->libraryDiscovery);

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy'),
        $this->equalTo("script-src 'self'; style-src 'self'")
      );

    $subscriber->onKernelResponse($this->event);
  }

}
