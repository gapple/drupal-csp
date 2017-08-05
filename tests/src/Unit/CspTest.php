<?php

namespace Drupal\Tests\csp\Unit;

use Drupal\csp\Csp;
use Drupal\Tests\UnitTestCase;

/**
 * Test Csp behaviour.
 *
 * @coversDefaultClass Drupal\csp\Csp
 * @group csp
 */
class CspTest extends UnitTestCase {

  /**
   * @covers ::reportOnly
   * @covers ::getHeaderName
   */
  public function testReportOnly() {
    $policy = new Csp();

    $this->assertEquals(
      "Content-Security-Policy",
      $policy->getHeaderName()
    );

    $policy->reportOnly();
    $this->assertEquals(
      "Content-Security-Policy-Report-Only",
      $policy->getHeaderName()
    );

    $policy->reportOnly(FALSE);
    $this->assertEquals(
      "Content-Security-Policy",
      $policy->getHeaderName()
    );
  }

  /**
   * @covers ::setDirective
   *
   * @expectedException \InvalidArgumentException
   */
  public function testSetInvalidPolicy() {
    $policy = new Csp();

    $policy->setDirective('foo', Csp::POLICY_SELF);
  }

  /**
   * @covers ::appendDirective
   *
   * @expectedException \InvalidArgumentException
   */
  public function testAppendInvalidPolicy() {
    $policy = new Csp();

    $policy->appendDirective('foo', Csp::POLICY_SELF);
  }

  /**
   * @covers ::setDirective
   * @covers ::getHeaderValue
   */
  public function testSetSingle() {
    $policy = new Csp();

    $policy->setDirective('default-src', Csp::POLICY_SELF);

    $this->assertEquals(
      "default-src 'self'",
      $policy->getHeaderValue()
    );
  }

  /**
   * @covers ::appendDirective
   * @covers ::getHeaderValue
   */
  public function testAppendSingle() {
    $policy = new Csp();

    $policy->appendDirective('default-src', Csp::POLICY_SELF);

    $this->assertEquals(
      "default-src 'self'",
      $policy->getHeaderValue()
    );
  }

  /**
   * @covers ::setDirective
   * @covers ::getHeaderValue
   */
  public function testSetMultiple() {
    $policy = new Csp();

    $policy->setDirective('default-src', Csp::POLICY_SELF);
    $policy->setDirective('default-src', [Csp::POLICY_SELF, 'example.com']);
    $policy->setDirective('script-src', Csp::POLICY_SELF . ' example.com');

    $this->assertEquals(
      "default-src 'self' example.com; script-src 'self' example.com",
      $policy->getHeaderValue()
    );
  }

  /**
   * @covers ::appendDirective
   * @covers ::getHeaderValue
   */
  public function testAppendMultiple() {
    $policy = new Csp();

    $policy->appendDirective('default-src', Csp::POLICY_SELF);
    $policy->appendDirective('script-src', [Csp::POLICY_SELF, 'example.com']);
    $policy->appendDirective('default-src', 'example.com');

    $this->assertEquals(
      "default-src 'self' example.com; script-src 'self' example.com",
      $policy->getHeaderValue()
    );
  }

  /**
   * @covers ::setDirective
   * @covers ::getHeaderValue
   */
  public function testSetEmpty() {
    $policy = new Csp();

    $policy->setDirective('default-src', Csp::POLICY_SELF);
    $policy->setDirective('script-src', [Csp::POLICY_SELF]);
    $policy->setDirective('script-src', []);

    $this->assertEquals(
      "default-src 'self'",
      $policy->getHeaderValue()
    );

    $policy = new Csp();

    $policy->setDirective('default-src', Csp::POLICY_SELF);
    $policy->setDirective('script-src', [Csp::POLICY_SELF]);
    $policy->setDirective('script-src', '');

    $this->assertEquals(
      "default-src 'self'",
      $policy->getHeaderValue()
    );
  }

  /**
   * @covers ::appendDirective
   * @covers ::getHeaderValue
   */
  public function testAppendEmpty() {
    $policy = new Csp();

    $policy->appendDirective('default-src', Csp::POLICY_SELF);
    $policy->appendDirective('default-src', '');
    $policy->appendDirective('script-src', []);

    $this->assertEquals(
      "default-src 'self'",
      $policy->getHeaderValue()
    );

    $policy = new Csp();

    $policy->setDirective('default-src', Csp::POLICY_SELF);
    $policy->setDirective('script-src', [Csp::POLICY_SELF]);
    $policy->setDirective('script-src', '');

    $this->assertEquals(
      "default-src 'self'",
      $policy->getHeaderValue()
    );
  }

  /**
   * @covers ::setDirective
   * @covers ::appendDirective
   * @covers ::getHeaderValue
   */
  public function testDuplicate() {
    $policy = new Csp();

    $policy->setDirective('default-src', [Csp::POLICY_SELF, Csp::POLICY_SELF]);
    $policy->setDirective('script-src', 'example.com example.com');

    $policy->setDirective('style-src', [Csp::POLICY_SELF, Csp::POLICY_SELF]);
    $policy->appendDirective('style-src', [Csp::POLICY_SELF, Csp::POLICY_SELF]);

    $this->assertEquals(
      "default-src 'self'; script-src example.com; style-src 'self'",
      $policy->getHeaderValue()
    );
  }

  /**
   * @covers ::removeDirective
   * @covers ::getHeaderValue
   */
  public function testRemove() {
    $policy = new Csp();

    $policy->setDirective('default-src', [Csp::POLICY_SELF]);
    $policy->setDirective('script-src', 'example.com');

    $policy->removeDirective('script-src');

    $this->assertEquals(
      "default-src 'self'",
      $policy->getHeaderValue()
    );
  }

  /**
   * @covers ::removeDirective
   *
   * @expectedException \InvalidArgumentException
   */
  public function testRemoveInvalid() {
    $policy = new Csp();

    $policy->removeDirective('foo');
  }

  /**
   * @covers ::appendDirective
   *
   * @expectedException \InvalidArgumentException
   */
  public function testInvalidValue() {
    $policy = new Csp();

    $policy->appendDirective('default-src', 12);
  }

  /**
   * @covers ::__toString
   */
  public function testToString() {
    $policy = new Csp();

    $policy->setDirective('default-src', Csp::POLICY_SELF);
    $policy->setDirective('script-src', Csp::POLICY_SELF);

    $this->assertEquals(
      "Content-Security-Policy: default-src 'self'; script-src 'self'",
      $policy->__toString()
    );
  }

}
