<?php

namespace Drupal\Tests\csp\Unit\EventSubscriber;

use Drupal\Core\Render\HtmlResponse;
use Drupal\csp\EventSubscriber\ResponseCspSubscriber;
use Drupal\Tests\UnitTestCase;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;

/**
 * @coversDefaultClass Drupal\csp\EventSubscriber\ResponseCspSubscriber
 * @group csp
 */
class ResponseCspSubscriberTest extends UnitTestCase {

  /**
   * Check the policy with CSS optimization disabled.
   *
   * @covers ::onKernelResponse
   */
  public function testUnoptimizedResponse() {
    $response = $this->getMockBuilder(HtmlResponse::class)
      ->disableOriginalConstructor()
      ->getMock();
    $response->headers = $this->getMockBuilder(ResponseHeaderBag::class)
      ->disableOriginalConstructor()
      ->getMock();

    /** @var \Symfony\Component\HttpKernel\Event\FilterResponseEvent|\PHPUnit_Framework_MockObject_MockObject $event */
    $event = $this->getMockBuilder(FilterResponseEvent::class)
      ->disableOriginalConstructor()
      ->getMock();
    $event->expects($this->any())
      ->method('isMasterRequest')
      ->willReturn(TRUE);
    $event->expects($this->any())
      ->method('getResponse')
      ->willReturn($response);

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit_Framework_MockObject_MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'system.performance' => [
        'css.preprocess' => FALSE,
      ],
    ]);

    $subscriber = new ResponseCspSubscriber($configFactory);

    $response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy-Report-Only'),
        $this->equalTo("default-src 'self'; style-src 'self' 'unsafe-inline'")
      );

    $subscriber->onKernelResponse($event);
  }

  /**
   * Check the policy with CSS optimization enabled.
   *
   * @covers ::onKernelResponse
   */
  public function testOptimizedResponse() {
    $response = $this->getMockBuilder(HtmlResponse::class)
      ->disableOriginalConstructor()
      ->getMock();
    $response->headers = $this->getMockBuilder(ResponseHeaderBag::class)
      ->disableOriginalConstructor()
      ->getMock();

    /** @var \Symfony\Component\HttpKernel\Event\FilterResponseEvent|\PHPUnit_Framework_MockObject_MockObject $event */
    $event = $this->getMockBuilder(FilterResponseEvent::class)
      ->disableOriginalConstructor()
      ->getMock();
    $event->expects($this->any())
      ->method('isMasterRequest')
      ->willReturn(TRUE);
    $event->expects($this->any())
      ->method('getResponse')
      ->willReturn($response);

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit_Framework_MockObject_MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'system.performance' => [
        'css.preprocess' => TRUE,
      ],
    ]);

    $subscriber = new ResponseCspSubscriber($configFactory);

    $response->headers->expects($this->once())
      ->method('set')
      ->with(
        $this->equalTo('Content-Security-Policy-Report-Only'),
        $this->equalTo("default-src 'self'")
      );

    $subscriber->onKernelResponse($event);
  }

}
