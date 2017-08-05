<?php

namespace Drupal\csp;

/**
 * A CSP Header.
 */
class Csp {

  const POLICY_ANY = "*";
  const POLICY_NONE = "'none'";
  const POLICY_SELF = "'self'";
  const POLICY_STRICT_DYNAMIC = "'strict-dynamic'";
  const POLICY_UNSAFE_EVAL = "'unsafe-eval'";
  const POLICY_UNSAFE_INLINE = "'unsafe-inline'";

  /**
   * The available policy directive keys.
   *
   * @var array
   */
  private static $directiveNames = [
    'base-uri',
    'default-src',
    'child-src',
    'connect-src',
    'font-src',
    'form-action',
    'frame-ancestors',
    'frame-src',
    'img-src',
    'media-src',
    'object-src',
    'plugin-types',
    'manifest-src',
    'script-src',
    'style-src',
  ];

  /**
   * If this policy is report-only.
   *
   * @var bool
   */
  protected $reportOnly = FALSE;

  /**
   * The policy directives.
   *
   * @var array
   */
  protected $directives = [];

  /**
   * Set the policy to report-only.
   *
   * @param bool $value
   *   The report-only status.
   */
  public function reportOnly($value = TRUE) {
    $this->reportOnly = $value;
  }

  /**
   * Add a new directive to the policy, or replace an existing directive.
   *
   * @param string $name
   *   The directive name.
   * @param array|string $value
   *   The directive value.
   */
  public function setDirective($name, $value) {
    if (!in_array($name, self::$directiveNames)) {
      throw new \InvalidArgumentException("Invalid directive name provided");
    }

    $this->directives[$name] = [];
    if (empty($value)) {
      return;
    }
    $this->appendDirective($name, $value);
  }

  /**
   * Append values to an existing directive.
   *
   * @param string $name
   *   The directive name.
   * @param array|string $value
   *   The directive value.
   */
  public function appendDirective($name, $value) {
    if (!in_array($name, self::$directiveNames)) {
      throw new \InvalidArgumentException("Invalid directive name provided");
    }

    if (empty($value)) {
      return;
    }

    if (gettype($value) === 'string') {
      $value = explode(' ', $value);
    }
    elseif (gettype($value) !== 'array') {
      throw new \InvalidArgumentException("Invalid directive value provided");
    }

    if (!isset($this->directives[$name])) {
      $this->directives[$name] = [];
    }

    $this->directives[$name] = array_merge($this->directives[$name], $value);
  }

  /**
   * Remove a directive from the policy.
   *
   * @param string $name
   *   The directive name.
   */
  public function removeDirective($name) {
    if (!in_array($name, self::$directiveNames)) {
      throw new \InvalidArgumentException("Invalid directive name provided");
    }

    unset($this->directives[$name]);
  }

  /**
   * Get the header name.
   *
   * @return string
   *   The header name.
   */
  public function getHeaderName() {
    return 'Content-Security-Policy' . ($this->reportOnly ? '-Report-Only' : '');
  }

  /**
   * Get the header value.
   *
   * @return string
   *   The header value.
   */
  public function getHeaderValue() {
    $output = '';

    foreach ($this->directives as $name => $value) {
      if (empty($value)) {
        continue;
      }
      $value = array_unique($value);
      $output .= $name . ' ' . implode(' ', $value) . '; ';
    }

    return substr($output, 0, -2);
  }

  /**
   * Create the string header representation.
   *
   * @return string
   *   The full header string.
   */
  public function __toString() {
    return $this->getHeaderName() . ': ' . $this->getHeaderValue();
  }

}
