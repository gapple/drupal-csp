<?php

namespace Drupal\Tests\csp\Unit\EventSubscriber;

use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Render\HtmlResponse;
use Drupal\csp\EventSubscriber\ResponseCspSubscriber;
use Drupal\csp\LibraryPolicyBuilder;
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
   * Mock Module Handler.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface|\PHPUnit_Framework_MockObject_MockObject
   */
  protected $moduleHandler;

  /**
   * The Library Policy service.
   *
   * @var \Drupal\csp\LibraryPolicyBuilder
   */
  private $libraryPolicy;

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

    $this->moduleHandler = $this->getMockBuilder(ModuleHandler::class)
      ->disableOriginalConstructor()
      ->getMock();

    $this->libraryPolicy = $this->getMockBuilder(LibraryPolicyBuilder::class)
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

    $this->libraryPolicy->expects($this->any())
      ->method('getSourcesForActiveTheme')
      ->willReturn([]);

    $subscriber = new ResponseCspSubscriber($configFactory, $this->moduleHandler, $this->libraryPolicy);

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy-Report-Only'),
        $this->equalTo("script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
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

    $this->libraryPolicy->expects($this->any())
      ->method('getSourcesForActiveTheme')
      ->willReturn([]);

    $subscriber = new ResponseCspSubscriber($configFactory, $this->moduleHandler, $this->libraryPolicy);

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy-Report-Only'),
        $this->equalTo("script-src 'self' 'unsafe-inline'; style-src 'self'")
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

    $subscriber = new ResponseCspSubscriber($configFactory, $this->moduleHandler, $this->libraryPolicy);

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy-Report-Only'),
        $this->equalTo("script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
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

    $subscriber = new ResponseCspSubscriber($configFactory, $this->moduleHandler, $this->libraryPolicy);

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy-Report-Only'),
        $this->equalTo("script-src 'self' 'unsafe-inline'; style-src 'self'")
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

    $subscriber = new ResponseCspSubscriber($configFactory, $this->moduleHandler, $this->libraryPolicy);

    $this->response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy'),
        $this->equalTo("script-src 'self' 'unsafe-inline'; style-src 'self'")
      );

    $subscriber->onKernelResponse($this->event);
  }

}
