<?php

namespace Drupal\Tests\csp\Unit\EventSubscriber;

use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Render\HtmlResponse;
use Drupal\csp\Csp;
use Drupal\csp\CspEvents;
use Drupal\csp\Event\PolicyAlterEvent;
use Drupal\csp\EventSubscriber\CoreCspSubscriber;
use Drupal\csp\EventSubscriber\Ie9CspSubscriber;
use Drupal\Tests\UnitTestCase;

/**
 * @coversDefaultClass \Drupal\csp\EventSubscriber\Ie9CspSubscriber
 * @group csp
 */
class Ie9CspSubscriberTest extends UnitTestCase {

  /**
   * The Module Handler service.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface|\PHPUnit\Framework\MockObject\MockObject
   */
  private $moduleHandler;

  /**
   * The response object.
   *
   * @var \Drupal\Core\Render\HtmlResponse|\PHPUnit\Framework\MockObject\MockObject
   */
  private $response;

  /**
   * {@inheritdoc}
   */
  public function setUp(): void {
    parent::setUp();

    $this->moduleHandler = $this->getMockBuilder(ModuleHandlerInterface::class)
      ->disableOriginalConstructor()
      ->getMock();

    $this->response = $this->getMockBuilder(HtmlResponse::class)
      ->disableOriginalConstructor()
      ->getMock();
  }

  /**
   * Check that the subscriber listens to the Policy Alter event.
   *
   * @covers ::getSubscribedEvents
   */
  public function testSubscribedEvents() {
    $this->assertArrayHasKey(CspEvents::POLICY_ALTER, CoreCspSubscriber::getSubscribedEvents());
  }

  /**
   * Shouldn't alter the policy if no directives are enabled.
   *
   * @covers ::onCspPolicyAlter
   */
  public function testNoDirectives() {
    $this->moduleHandler->method('moduleExists')
      ->willReturn($this->callback(function ($parameter) {
        return $parameter === 'ie9';
      }));

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit_Framework_MockObject_MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'system.performance' => [
        'css.preprocess' => FALSE,
      ],
    ]);

    $policy = new Csp();
    $alterEvent = new PolicyAlterEvent($policy, $this->response);

    $subscriber = new Ie9CspSubscriber($configFactory, $this->moduleHandler);
    $subscriber->onCspPolicyAlter($alterEvent);

    $this->assertFalse($alterEvent->getPolicy()->hasDirective('script-src'));
    $this->assertFalse($alterEvent->getPolicy()->hasDirective('script-src-attr'));
    $this->assertFalse($alterEvent->getPolicy()->hasDirective('script-src-elem'));
  }

  /**
   * Test that enabled style directives are modified.
   *
   * @covers ::onCspPolicyAlter
   */
  public function testStyle() {
    $this->moduleHandler->method('moduleExists')
      ->willReturn($this->callback(function ($parameter) {
        return $parameter === 'ie9';
      }));

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit_Framework_MockObject_MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'system.performance' => [
        'css.preprocess' => FALSE,
      ],
    ]);

    $policy = new Csp();
    $policy->setDirective('default-src', [Csp::POLICY_ANY]);
    $policy->setDirective('style-src', [Csp::POLICY_SELF]);
    $policy->setDirective('style-src-attr', [Csp::POLICY_SELF]);
    $policy->setDirective('style-src-elem', [Csp::POLICY_SELF]);

    $alterEvent = new PolicyAlterEvent($policy, $this->response);

    $subscriber = new Ie9CspSubscriber($configFactory, $this->moduleHandler);
    $subscriber->onCspPolicyAlter($alterEvent);

    $this->assertEquals(
      [Csp::POLICY_SELF, Csp::POLICY_UNSAFE_INLINE],
      $alterEvent->getPolicy()->getDirective('style-src')
    );
    $this->assertEquals(
      [Csp::POLICY_SELF],
      $alterEvent->getPolicy()->getDirective('style-src-attr')
    );
    $this->assertEquals(
      [Csp::POLICY_SELF, Csp::POLICY_UNSAFE_INLINE],
      $alterEvent->getPolicy()->getDirective('style-src-elem')
    );
  }

  /**
   * Test that style directive are not modified if CSS preprocessing is enabled.
   *
   * @covers ::onCspPolicyAlter
   */
  public function testPreprocessEnabled() {
    $this->moduleHandler->method('moduleExists')
      ->willReturn($this->callback(function ($parameter) {
        return $parameter === 'ie9';
      }));

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit_Framework_MockObject_MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'system.performance' => [
        'css.preprocess' => TRUE,
      ],
    ]);

    $policy = new Csp();
    $policy->setDirective('default-src', [Csp::POLICY_ANY]);
    $policy->setDirective('style-src', [Csp::POLICY_SELF]);
    $policy->setDirective('style-src-attr', [Csp::POLICY_SELF]);
    $policy->setDirective('style-src-elem', [Csp::POLICY_SELF]);

    $alterEvent = new PolicyAlterEvent($policy, $this->response);

    $subscriber = new Ie9CspSubscriber($configFactory, $this->moduleHandler);
    $subscriber->onCspPolicyAlter($alterEvent);

    $this->assertEquals(
      [Csp::POLICY_SELF],
      $alterEvent->getPolicy()->getDirective('style-src')
    );
    $this->assertEquals(
      [Csp::POLICY_SELF],
      $alterEvent->getPolicy()->getDirective('style-src-attr')
    );
    $this->assertEquals(
      [Csp::POLICY_SELF],
      $alterEvent->getPolicy()->getDirective('style-src-elem')
    );
  }

  /**
   * Test style-src-elem fallback if style-src enabled.
   *
   * @covers ::onCspPolicyAlter
   */
  public function testStyleElemFallback() {
    $this->moduleHandler->method('moduleExists')
      ->with($this->equalTo('ie9'))
      ->willReturn(TRUE);

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit_Framework_MockObject_MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'system.performance' => [
        'css.preprocess' => FALSE,
      ],
    ]);

    $policy = new Csp();
    $policy->setDirective('default-src', [Csp::POLICY_ANY]);
    $policy->setDirective('style-src', [Csp::POLICY_SELF]);

    $alterEvent = new PolicyAlterEvent($policy, $this->response);

    $subscriber = new Ie9CspSubscriber($configFactory, $this->moduleHandler);
    $subscriber->onCspPolicyAlter($alterEvent);

    $this->assertEquals(
      [Csp::POLICY_SELF, Csp::POLICY_UNSAFE_INLINE],
      $alterEvent->getPolicy()->getDirective('style-src')
    );
    $this->assertEquals(
      [Csp::POLICY_SELF],
      $alterEvent->getPolicy()->getDirective('style-src-attr')
    );
    $this->assertEquals(
      [Csp::POLICY_SELF, Csp::POLICY_UNSAFE_INLINE],
      array_unique($alterEvent->getPolicy()->getDirective('style-src-elem'))
    );
  }

  /**
   * Test style-src-elem fallback if default-src enabled.
   *
   * @covers ::onCspPolicyAlter
   */
  public function testStyleDefaultFallback() {
    $this->moduleHandler->method('moduleExists')
      ->willReturn($this->callback(function ($parameter) {
        return $parameter === 'ie9';
      }));

    /** @var \Drupal\Core\Config\ConfigFactoryInterface|\PHPUnit_Framework_MockObject_MockObject $configFactory */
    $configFactory = $this->getConfigFactoryStub([
      'system.performance' => [
        'css.preprocess' => FALSE,
      ],
    ]);

    $policy = new Csp();
    $policy->setDirective('default-src', [Csp::POLICY_SELF]);

    $alterEvent = new PolicyAlterEvent($policy, $this->response);

    $subscriber = new Ie9CspSubscriber($configFactory, $this->moduleHandler);
    $subscriber->onCspPolicyAlter($alterEvent);

    $this->assertEquals(
      [Csp::POLICY_SELF, Csp::POLICY_UNSAFE_INLINE],
      $alterEvent->getPolicy()->getDirective('style-src')
    );
    $this->assertEquals(
      [Csp::POLICY_SELF],
      $alterEvent->getPolicy()->getDirective('style-src-attr')
    );
    $this->assertEquals(
      [Csp::POLICY_SELF, Csp::POLICY_UNSAFE_INLINE],
      array_unique($alterEvent->getPolicy()->getDirective('style-src-elem'))
    );
  }

}
