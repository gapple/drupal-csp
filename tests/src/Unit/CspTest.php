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
   * Test calculating hash values.
   *
   * @covers ::calculateHash
   */
  public function testHash() {
    $this->assertEquals(
      'sha256-BnZSlC9IkS7BVcseRf0CAOmLntfifZIosT2C1OMQ088=',
      Csp::calculateHash('alert("Hello World");')
    );

    $this->assertEquals(
      'sha256-BnZSlC9IkS7BVcseRf0CAOmLntfifZIosT2C1OMQ088=',
      Csp::calculateHash('alert("Hello World");', 'sha256')
    );

    $this->assertEquals(
      'sha384-iZxROpttQr5JcGhwPlHbUPBm+IHbO2CwTxLGhVoZXCIIpjSZo+Ourcmqw1QHOpGM',
      Csp::calculateHash('alert("Hello World");', 'sha384')
    );

    $this->assertEquals(
      'sha512-6/WbXCJEH9R1/effxooQuXLAsm6xIsfGMK6nFa7TG76VuHZJVRZHIirKrXi/Pib8QbQmkzpo5K/3Ye+cD46ADQ==',
      Csp::calculateHash('alert("Hello World");', 'sha512')
    );
  }

  /**
   * Test specifying an invalid hash algorithm.
   *
   * @covers ::calculateHash
   * @expectedException \InvalidArgumentException
   */
  public function testInvalidHashAlgo() {
    Csp::calculateHash('alert("Hello World");', 'md5');
  }

  /**
   * Test that changing the policy's report-only flag updates the header name.
   *
   * @covers ::reportOnly
   * @covers ::isReportOnly
   * @covers ::getHeaderName
   */
  public function testReportOnly() {
    $policy = new Csp();

    $this->assertFalse($policy->isReportOnly());
    $this->assertEquals(
      "Content-Security-Policy",
      $policy->getHeaderName()
    );

    $policy->reportOnly();
    $this->assertTrue($policy->isReportOnly());
    $this->assertEquals(
      "Content-Security-Policy-Report-Only",
      $policy->getHeaderName()
    );

    $policy->reportOnly(FALSE);
    $this->assertFalse($policy->isReportOnly());
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
   * @covers ::validateDirectiveName
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
   * @covers ::validateDirectiveName
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
   * @covers ::hasDirective
   * @covers ::getDirective
   * @covers ::isValidDirectiveName
   * @covers ::validateDirectiveName
   * @covers ::getHeaderValue
   */
  public function testSetSingle() {
    $policy = new Csp();

    $policy->setDirective('default-src', Csp::POLICY_SELF);

    $this->assertTrue($policy->hasDirective('default-src'));
    $this->assertEquals(
      $policy->getDirective('default-src'),
      ["'self'"]
    );
    $this->assertEquals(
      "default-src 'self'",
      $policy->getHeaderValue()
    );
  }

  /**
   * Test appending a single value to an uninitialized directive.
   *
   * @covers ::appendDirective
   * @covers ::hasDirective
   * @covers ::getDirective
   * @covers ::isValidDirectiveName
   * @covers ::validateDirectiveName
   * @covers ::getHeaderValue
   */
  public function testAppendSingle() {
    $policy = new Csp();

    $policy->appendDirective('default-src', Csp::POLICY_SELF);

    $this->assertTrue($policy->hasDirective('default-src'));
    $this->assertEquals(
      $policy->getDirective('default-src'),
      ["'self'"]
    );
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

    $policy->setDirective('default-src', Csp::POLICY_ANY);
    $policy->setDirective('default-src', [Csp::POLICY_SELF, 'one.example.com']);
    $policy->setDirective('script-src', Csp::POLICY_SELF . ' two.example.com');
    $policy->setDirective('upgrade-insecure-requests', TRUE);
    $policy->setDirective('report-uri', 'example.com/report-uri');

    $this->assertEquals(
      "upgrade-insecure-requests; default-src 'self' one.example.com; script-src 'self' two.example.com; report-uri example.com/report-uri",
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
    $policy->appendDirective('script-src', [Csp::POLICY_SELF, 'two.example.com']);
    $policy->appendDirective('default-src', 'one.example.com');

    $this->assertEquals(
      "default-src 'self' one.example.com; script-src 'self' two.example.com",
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
   * Appending to a directive if it or a fallback is enabled.
   *
   * @covers ::fallbackAwareAppendIfEnabled
   */
  public function testFallbackAwareAppendIfEnabled() {
    // If no relevant directives are enabled, they should not change.
    $policy = new Csp();
    $policy->setDirective('style-src', Csp::POLICY_SELF);
    $policy->fallbackAwareAppendIfEnabled('script-src-attr', Csp::POLICY_UNSAFE_INLINE);
    $this->assertFalse($policy->hasDirective('default-src'));
    $this->assertFalse($policy->hasDirective('script-src'));
    $this->assertFalse($policy->hasDirective('script-src-attr'));

    // Script-src-attr should copy value from default-src.  Script-src should
    // not be changed.
    $policy = new Csp();
    $policy->setDirective('default-src', Csp::POLICY_SELF);
    $policy->fallbackAwareAppendIfEnabled('script-src-attr', Csp::POLICY_UNSAFE_INLINE);
    $this->assertEquals(
      [Csp::POLICY_SELF],
      $policy->getDirective('default-src')
    );
    $this->assertFalse($policy->hasDirective('script-src'));
    $this->assertEquals(
      [Csp::POLICY_SELF, Csp::POLICY_UNSAFE_INLINE],
      $policy->getDirective('script-src-attr')
    );

    // Script-src-attr should copy value from script-src.
    $policy = new Csp();
    $policy->setDirective('script-src', Csp::POLICY_SELF);
    $policy->fallbackAwareAppendIfEnabled('script-src-attr', Csp::POLICY_UNSAFE_INLINE);
    $this->assertFalse($policy->hasDirective('default-src'));
    $this->assertEquals(
      [Csp::POLICY_SELF],
      $policy->getDirective('script-src')
    );
    $this->assertEquals(
      [Csp::POLICY_SELF, Csp::POLICY_UNSAFE_INLINE],
      $policy->getDirective('script-src-attr')
    );

    // Script-src-attr should only append to existing value if enabled.
    $policy = new Csp();
    $policy->setDirective('script-src', Csp::POLICY_SELF);
    $policy->setDirective('script-src-attr', []);
    $policy->fallbackAwareAppendIfEnabled('script-src-attr', Csp::POLICY_UNSAFE_INLINE);
    $this->assertFalse($policy->hasDirective('default-src'));
    $this->assertEquals(
      [Csp::POLICY_SELF],
      $policy->getDirective('script-src')
    );
    $this->assertEquals(
      [Csp::POLICY_UNSAFE_INLINE],
      $policy->getDirective('script-src-attr')
    );
  }

  /**
   * Appending to a directive if its fallback includes 'none'.
   *
   * @covers ::fallbackAwareAppendIfEnabled
   */
  public function testFallbackAwareAppendIfEnabledNone() {
    // New directive should be enabled with only provided value.
    $policy = new Csp();
    $policy->setDirective('default-src', Csp::POLICY_NONE);
    $policy->fallbackAwareAppendIfEnabled(
      'script-src-attr',
      Csp::POLICY_UNSAFE_INLINE
    );
    $this->assertEquals(
      [Csp::POLICY_NONE],
      $policy->getDirective('default-src')
    );
    $this->assertFalse($policy->hasDirective('script-src'));
    $this->assertEquals(
      [Csp::POLICY_UNSAFE_INLINE],
      $policy->getDirective('script-src-attr')
    );

    // Additional values in fallback should be ignored if 'none' is present.
    $policy = new Csp();
    $policy->setDirective('script-src', [Csp::POLICY_NONE, 'https://example.org']);
    $policy->fallbackAwareAppendIfEnabled(
      'script-src-attr',
      Csp::POLICY_UNSAFE_INLINE
    );
    $this->assertEquals(
      [Csp::POLICY_UNSAFE_INLINE],
      $policy->getDirective('script-src-attr')
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

    // Provide identical sources in an array.
    $policy->setDirective('default-src', [Csp::POLICY_SELF, Csp::POLICY_SELF]);
    // Provide identical sources in a string.
    $policy->setDirective('script-src', 'one.example.com one.example.com');

    // Provide identical sources through both set and append.
    $policy->setDirective('style-src', ['two.example.com', 'two.example.com']);
    $policy->appendDirective('style-src', ['two.example.com', 'two.example.com']);

    $this->assertEquals(
      "default-src 'self'; script-src one.example.com; style-src two.example.com",
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
   * @covers ::validateDirectiveName
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
   * Test optimizing policy based on directives which fallback to default-src.
   *
   * @covers ::getHeaderValue
   * @covers ::getDirectiveFallbackList
   * @covers ::reduceSourceList
   */
  public function testDefaultSrcFallback() {
    $policy = new Csp();
    $policy->setDirective('default-src', Csp::POLICY_SELF);

    // Directives which fallback to default-src.
    $policy->setDirective('script-src', Csp::POLICY_SELF);
    $policy->setDirective('style-src', Csp::POLICY_SELF);
    $policy->setDirective('worker-src', Csp::POLICY_SELF);
    $policy->setDirective('child-src', Csp::POLICY_SELF);
    $policy->setDirective('connect-src', Csp::POLICY_SELF);
    $policy->setDirective('manifest-src', Csp::POLICY_SELF);
    $policy->setDirective('prefetch-src', Csp::POLICY_SELF);
    $policy->setDirective('object-src', Csp::POLICY_SELF);
    $policy->setDirective('frame-src', Csp::POLICY_SELF);
    $policy->setDirective('media-src', Csp::POLICY_SELF);
    $policy->setDirective('font-src', Csp::POLICY_SELF);
    $policy->setDirective('img-src', Csp::POLICY_SELF);

    // Directives which do not fallback to default-src.
    $policy->setDirective('base-uri', Csp::POLICY_SELF);
    $policy->setDirective('form-action', Csp::POLICY_SELF);
    $policy->setDirective('frame-ancestors', Csp::POLICY_SELF);
    $policy->setDirective('navigate-to', Csp::POLICY_SELF);

    $this->assertEquals(
      "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'; navigate-to 'self'",
      $policy->getHeaderValue()
    );
  }

  /**
   * Test optimizing policy based on the worker-src fallback list.
   *
   * @covers ::getHeaderValue
   * @covers ::getDirectiveFallbackList
   * @covers ::reduceSourceList
   */
  public function testWorkerSrcFallback() {
    $policy = new Csp();

    // Fallback should progresses as more policies in the list are added.
    $policy->setDirective('worker-src', Csp::POLICY_SELF);
    $this->assertEquals(
      "worker-src 'self'",
      $policy->getHeaderValue()
    );

    $policy->setDirective('child-src', Csp::POLICY_SELF);
    $this->assertEquals(
      "child-src 'self'",
      $policy->getHeaderValue()
    );

    $policy->setDirective('script-src', Csp::POLICY_SELF);
    $this->assertEquals(
      "script-src 'self'",
      $policy->getHeaderValue()
    );

    $policy->setDirective('default-src', Csp::POLICY_SELF);
    $this->assertEquals(
      "default-src 'self'",
      $policy->getHeaderValue()
    );

    // A missing directive from the list should not prevent fallback.
    $policy->removeDirective('child-src');
    $this->assertEquals(
      "default-src 'self'",
      $policy->getHeaderValue()
    );

    // Fallback should only progress to the nearest matching directive.
    // Since child-src differs from worker-src, both should be included.
    // script-src does not appear since it matches default-src.
    $policy->setDirective('child-src', [Csp::POLICY_SELF, 'example.com']);
    $this->assertEquals(
      "worker-src 'self'; default-src 'self'; child-src 'self' example.com",
      $policy->getHeaderValue()
    );

    // Fallback should only progress to the nearest matching directive.
    // worker-src now matches child-src, so it should be removed.
    $policy->setDirective('worker-src', [Csp::POLICY_SELF, 'example.com']);
    $this->assertEquals(
      "default-src 'self'; child-src 'self' example.com",
      $policy->getHeaderValue()
    );
  }

  /**
   * Test optimizing policy based on the script-src fallback list.
   *
   * @covers ::getHeaderValue
   * @covers ::getDirectiveFallbackList
   * @covers ::reduceSourceList
   */
  public function testScriptSrcFallback() {
    $policy = new Csp();

    $policy->setDirective('default-src', Csp::POLICY_SELF);
    $policy->setDirective('script-src', [Csp::POLICY_SELF, Csp::POLICY_UNSAFE_INLINE]);
    // script-src-elem should not fall back to default-src.
    $policy->setDirective('script-src-elem', Csp::POLICY_SELF);
    $policy->setDirective('script-src-attr', Csp::POLICY_UNSAFE_INLINE);
    $this->assertEquals(
      "default-src 'self'; script-src 'self' 'unsafe-inline'; script-src-elem 'self'; script-src-attr 'unsafe-inline'",
      $policy->getHeaderValue()
    );

    $policy->setDirective('script-src-attr', [Csp::POLICY_SELF, Csp::POLICY_UNSAFE_INLINE]);
    $this->assertEquals(
      "default-src 'self'; script-src 'self' 'unsafe-inline'; script-src-elem 'self'",
      $policy->getHeaderValue()
    );
  }

  /**
   * Test optimizing policy based on the style-src fallback list.
   *
   * @covers ::getHeaderValue
   * @covers ::getDirectiveFallbackList
   * @covers ::reduceSourceList
   */
  public function testStyleSrcFallback() {
    $policy = new Csp();

    $policy->setDirective('default-src', Csp::POLICY_SELF);
    $policy->setDirective('style-src', [Csp::POLICY_SELF, Csp::POLICY_UNSAFE_INLINE]);
    // style-src-elem should not fall back to default-src.
    $policy->setDirective('style-src-elem', Csp::POLICY_SELF);
    $policy->setDirective('style-src-attr', Csp::POLICY_UNSAFE_INLINE);
    $this->assertEquals(
      "default-src 'self'; style-src 'self' 'unsafe-inline'; style-src-elem 'self'; style-src-attr 'unsafe-inline'",
      $policy->getHeaderValue()
    );

    $policy->setDirective('style-src-attr', [Csp::POLICY_SELF, Csp::POLICY_UNSAFE_INLINE]);
    $this->assertEquals(
      "default-src 'self'; style-src 'self' 'unsafe-inline'; style-src-elem 'self'",
      $policy->getHeaderValue()
    );
  }

  /**
   * Test reducing the source list when 'none' is included.
   *
   * @covers ::reduceSourceList
   */
  public function testReduceSourceListWithNone() {
    $policy = new Csp();

    $policy->setDirective('object-src', [
      Csp::POLICY_NONE,
      'example.com',
      "'hash-123abc'",
    ]);
    $this->assertEquals(
      "object-src 'none'",
      $policy->getHeaderValue()
    );
  }

  /**
   * Test reducing source list when any host allowed.
   *
   * @covers ::reduceSourceList
   */
  public function testReduceSourceListAny() {
    $policy = new Csp();

    $policy->setDirective('default-src', [
      Csp::POLICY_ANY,
      // Hosts and network protocols should be removed.
      'example.com',
      'https://example.com',
      'http:',
      'https:',
      'ftp:',
      'ws:',
      'wss:',
      // Non-network protocols should be kept.
      'data:',
      // Additional keywords should be kept.
      Csp::POLICY_UNSAFE_INLINE,
      "'hash-123abc'",
      "'nonce-abc123'",
    ]);
    $this->assertEquals(
      "default-src * data: 'unsafe-inline' 'hash-123abc' 'nonce-abc123'",
      $policy->getHeaderValue()
    );
  }

  /**
   * Test reducing the source list when 'http:' is included.
   *
   * @covers ::reduceSourceList
   */
  public function testReduceSourceListWithHttp() {
    $policy = new Csp();

    $policy->setDirective('default-src', [
      'http:',
      // Hosts without protocol should be kept.
      // (e.g. this would allow ftp://example.com)
      'example.com',
      // HTTP hosts should be removed.
      'http://example.org',
      'https://example.net',
      // Other network protocols should be kept.
      'ftp:',
      // Non-network protocols should be kept.
      'data:',
      // Additional keywords should be kept.
      Csp::POLICY_UNSAFE_INLINE,
      "'hash-123abc'",
      "'nonce-abc123'",
    ]);

    $this->assertEquals(
      "default-src http: example.com ftp: data: 'unsafe-inline' 'hash-123abc' 'nonce-abc123'",
      $policy->getHeaderValue()
    );
  }

  /**
   * Test reducing the source list when 'https:' is included.
   *
   * @covers ::reduceSourceList
   */
  public function testReduceSourceListWithHttps() {
    $policy = new Csp();

    $policy->setDirective('default-src', [
      'https:',
      // Non-secure hosts should be kept.
      'example.com',
      'http://example.org',
      // Secure Hosts should be removed.
      'https://example.net',
      // Other network protocols should be kept.
      'ftp:',
      // Non-network protocols should be kept.
      'data:',
      // Additional keywords should be kept.
      Csp::POLICY_UNSAFE_INLINE,
      "'hash-123abc'",
      "'nonce-abc123'",
    ]);

    $this->assertEquals(
      "default-src https: example.com http://example.org ftp: data: 'unsafe-inline' 'hash-123abc' 'nonce-abc123'",
      $policy->getHeaderValue()
    );
  }

  /**
   * Test reducing the source list when 'ws:' is included.
   *
   * @covers ::reduceSourceList
   */
  public function testReduceSourceListWithWs() {
    $policy = new Csp();

    $policy->setDirective('default-src', [
      'https:',
      'ws:',
      // Hosts without protocol should be kept.
      // (e.g. this would allow ftp://example.com)
      'example.com',
      // HTTP hosts should be removed.
      'ws://connect.example.org',
      'wss://connect.example.net',
      // Other network protocols should be kept.
      'ftp:',
      // Non-network protocols should be kept.
      'data:',
      // Additional keywords should be kept.
      Csp::POLICY_UNSAFE_INLINE,
      "'hash-123abc'",
      "'nonce-abc123'",
    ]);

    $this->assertEquals(
      "default-src https: ws: example.com ftp: data: 'unsafe-inline' 'hash-123abc' 'nonce-abc123'",
      $policy->getHeaderValue()
    );
  }

  /**
   * Test reducing the source list when 'wss:' is included.
   *
   * @covers ::reduceSourceList
   */
  public function testReduceSourceListWithWss() {
    $policy = new Csp();

    $policy->setDirective('default-src', [
      'https:',
      'wss:',
      // Non-secure hosts should be kept.
      'example.com',
      'ws://connect.example.org',
      // Secure Hosts should be removed.
      'wss://connect.example.net',
      // Other network protocols should be kept.
      'ftp:',
      // Non-network protocols should be kept.
      'data:',
      // Additional keywords should be kept.
      Csp::POLICY_UNSAFE_INLINE,
      "'hash-123abc'",
      "'nonce-abc123'",
    ]);

    $this->assertEquals(
      "default-src https: wss: example.com ws://connect.example.org ftp: data: 'unsafe-inline' 'hash-123abc' 'nonce-abc123'",
      $policy->getHeaderValue()
    );
  }

  /**
   * @covers ::__toString
   */
  public function testToString() {
    $policy = new Csp();

    $policy->setDirective('default-src', Csp::POLICY_SELF);
    $policy->setDirective('script-src', [Csp::POLICY_SELF, 'example.com']);

    $this->assertEquals(
      "Content-Security-Policy: default-src 'self'; script-src 'self' example.com",
      $policy->__toString()
    );
  }

}
