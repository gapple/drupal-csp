<?php

namespace Drupal\Tests\csp\Form;

use Drupal\csp\Form\CspSettingsForm;
use Drupal\Tests\UnitTestCase;

/**
 * Test CSP Settings Form.
 *
 * @coversDefaultClass \Drupal\csp\Csp
 * @group csp
 */
class CspSettingsFormTest extends UnitTestCase {

  /**
   * Data provider of URLs for host source validity.
   *
   * @return array[]
   *   An array of [URL, isValid] tuples.
   */
  public function urlDataProvider() {
    return [
      'tld' => ['com', FALSE],
      'wildcard_tld' => ['*.com', FALSE],
      'bare' => ['example.com', TRUE],
      'bare_port' => ['example.com:1234', TRUE],
      'bare_path' => ['example.com/baz', TRUE],
      'bare_path_query' => ['example.com/baz?foo=false', FALSE],
      'bare_wild_subdomain' => ['*.example.com', TRUE],

      'subdomain' => ['foo.example.com', TRUE],
      'subdomains' => ['foo.bar.example.com', TRUE],
      'subdomains_path' => ['foo.bar.example.com/baz', TRUE],

      'http' => ['http://example.com', TRUE],
      'https' => ['https://example.com', TRUE],
      'ws' => ['ws://example.com', TRUE],
      'wss' => ['wss://example.com', TRUE],
      'https_port' => ['https://example.com:1234', TRUE],
      'https_port_path' => ['https://example.com:1234/baz', TRUE],
      'https_wild_subdomain' => ['https://*.example.com', TRUE],

      'ipv4' => ['192.168.0.1', TRUE],
      'https_ipv4' => ['https://192.168.0.1', TRUE],
      'https_ipv4_path' => ['https://192.168.0.1/baz', TRUE],
      'https_ipv4_port' => ['https://192.168.0.1:1234', TRUE],

      'ipv6' => ['[fd42:92f4:7eb8:c821:f685:9190:bf44:b2f5]', TRUE],
      'ipv6_short' => ['[fd42:92f4:7eb8:c821::b2f5]', TRUE],
      'https_ipv6' => ['https://[fd42:92f4:7eb8:c821:f685:9190:bf44:b2f5]', TRUE],
      'https_ipv6_short' => ['https://[fd42:92f4:7eb8:c821::b2f5]', TRUE],
      'https_ipv6_port' => ['https://[fd42:92f4:7eb8:c821:f685:9190:bf44:b2f5]:1234', TRUE],
      'https_ipv6_short_port' => ['https://[fd42:92f4:7eb8:c821::b2f5]:1234', TRUE],
      'https_ipv6_port_path' => ['https://[fd42:92f4:7eb8:c821:f685:9190:bf44:b2f5]:1234/baz', TRUE],

      'localhost' => ['localhost', TRUE],
      'https_localhost' => ['https://localhost', TRUE],
      'https_localhost_path' => ['https://localhost/baz', TRUE],
      'https_localhost_port' => ['https://localhost:1234', TRUE],
      'https_localhost_port_path' => ['https://localhost:1234/baz', TRUE],
    ];
  }

  /**
   * Valid host source values.
   *
   * @param string $url
   *   A URL.
   * @param bool $valid
   *   TRUE if the url should be valid.
   *
   * @dataProvider urlDataProvider
   */
  public function testIsValidHost(string $url, bool $valid = TRUE) {
    $this->assertEquals($valid, HostValidator::isValidHost($url));
  }

}

// @codingStandardsIgnoreStart
class HostValidator extends CspSettingsForm {
  public static function isValidHost($url): bool {
    return parent::isValidHost($url);
  }
}
// @codingStandardsIgnoreEnd