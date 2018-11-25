<?php

namespace Drupal\Tests\csp\Unit;

use Drupal\csp\Csp;
use Drupal\Tests\UnitTestCase;

/**
 * Test Csp behaviour.
 *
 * @coversDefaultClass \Drupal\csp\Csp
 * @group csp
 */
class CspTest extends UnitTestCase {

  /**
   * Test that changing the policy's report-only flag updates the header name.
   *
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
   * Test that invalid directive names cause an exception.
   *
   * @covers ::setDirective
   * @covers ::isValidDirectiveName
   *
   * @expectedException \InvalidArgumentException
   */
  public function testSetInvalidPolicy() {
    $policy = new Csp();

    $policy->setDirective('foo', Csp::POLICY_SELF);
  }

  /**
   * Test that invalid directive names cause an exception.
   *
   * @covers ::appendDirective
   * @covers ::isValidDirectiveName
   *
   * @expectedException \InvalidArgumentException
   */
  public function testAppendInvalidPolicy() {
    $policy = new Csp();

    $policy->appendDirective('foo', Csp::POLICY_SELF);
  }

  /**
   * Test setting a single value to a directive.
   *
   * @covers ::setDirective
   * @covers ::isValidDirectiveName
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
   * Test appending a single value to an uninitialized directive.
   *
   * @covers ::appendDirective
   * @covers ::isValidDirectiveName
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
   * Test that a directive is overridden when set with a new value.
   *
   * @covers ::setDirective
   * @covers ::isValidDirectiveName
   * @covers ::getHeaderValue
   */
  public function testSetMultiple() {
    $policy = new Csp();

    $policy->setDirective('default-src', Csp::POLICY_SELF);
    $policy->setDirective('default-src', [Csp::POLICY_SELF, 'example.com']);
    $policy->setDirective('script-src', Csp::POLICY_SELF . ' example.com');
    $policy->setDirective('report-uri', 'example.com/report-uri');

    $this->assertEquals(
      "default-src 'self' example.com; script-src 'self' example.com; report-uri example.com/report-uri",
      $policy->getHeaderValue()
    );
  }

  /**
   * Test that appending to a directive extends the existing value.
   *
   * @covers ::appendDirective
   * @covers ::isValidDirectiveName
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
   * Test that setting an empty value removes a directive.
   *
   * @covers ::setDirective
   * @covers ::isValidDirectiveName
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
   * Test that appending an empty value doesn't change the directive.
   *
   * @covers ::appendDirective
   * @covers ::isValidDirectiveName
   * @covers ::getHeaderValue
   */
  public function testAppendEmpty() {
    $policy = new Csp();

    $policy->appendDirective('default-src', Csp::POLICY_SELF);
    $this->assertEquals(
      "default-src 'self'",
      $policy->getHeaderValue()
    );

    $policy->appendDirective('default-src', '');
    $policy->appendDirective('script-src', []);
    $this->assertEquals(
      "default-src 'self'",
      $policy->getHeaderValue()
    );
  }

  /**
   * Test that source values are not repeated in the header.
   *
   * @covers ::setDirective
   * @covers ::appendDirective
   * @covers ::isValidDirectiveName
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
   * Test that removed directives are not output in the header.
   *
   * @covers ::removeDirective
   * @covers ::isValidDirectiveName
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
   * Test that removing an invalid directive name causes an exception.
   *
   * @covers ::removeDirective
   * @covers ::isValidDirectiveName
   *
   * @expectedException \InvalidArgumentException
   */
  public function testRemoveInvalid() {
    $policy = new Csp();

    $policy->removeDirective('foo');
  }

  /**
   * Test that invalid directive values cause an exception.
   *
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
