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
   * The available fetch directive keys.
   *
   * @var array
   */
  private static $fetchDirectiveNames = [
    'default-src',
    'child-src',
    'connect-src',
    'font-src',
    'frame-src',
    'img-src',
    'manifest-src',
    'media-src',
    'object-src',
    'script-src',
    'style-src',
    'worker-src',
  ];

  /**
   * The available document directive keys.
   *
   * @var array
   */
  private static $documentDirectiveNames = [
    'base-uri',
    'plugin-types',
    'sandbox',
  ];

  /**
   * The available navigation directive keys.
   *
   * @var array
   */
  private static $navigationDirectiveNames = [
    'form-action',
    'frame-ancestors',
  ];

  /**
   * The available reporting directive keys.
   *
   * @var array
   */
  private static $reportingDirectiveNames = [
    'report-uri',
    'report-to',
  ];

  /**
   * The available other directive keys.
   *
   * @var array
   */
  private static $otherDirectiveNames = [
    'block-all-mixed-content',
    'require-sri-for',
    'upgrade-insecure-requests',
  ];

  private static $directiveNameVariables = [
    'fetchDirectiveNames',
    'documentDirectiveNames',
    'navigationDirectiveNames',
    'reportingDirectiveNames',
    'otherDirectiveNames',
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
   * Check if a directive name is valid.
   *
   * @param string $name
   *   The directive name.
   *
   * @return bool
   *   True if the directive name is valid.
   */
  public static function isValidDirectiveName($name) {
    foreach (self::$directiveNameVariables as $directiveNameVariable) {
      if (in_array($name, static::${$directiveNameVariable})) {
        return TRUE;
      }
    }

    return FALSE;
  }

  /**
   * Get the valid directive names.
   *
   * @return array
   *   An array of directive names.
   */
  public static function getDirectiveNames() {
    $names = [];

    foreach (self::$directiveNameVariables as $directiveNameVariable) {
      $names = array_merge($names, static::${$directiveNameVariable});
    }

    return $names;
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
    if (!static::isValidDirectiveName($name)) {
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
    if (!static::isValidDirectiveName($name)) {
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
    if (!static::isValidDirectiveName($name)) {
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
    $output = [];

    foreach ($this->directives as $name => $value) {
      if (empty($value)) {
        continue;
      }

      // TODO reduce to minimal set
      // e.g.
      // - Wildcards and matching subdomains (*.example.com, sub.example.com)
      // - Protocols (example.com, https://example.com)
      // - Remove if same value as default-src
      $value = array_unique($value);
      $output[] = $name . ' ' . implode(' ', $value);
    }

    return implode('; ', $output);
  }

  /**
   * The report-uri endpoint.
   *
   * Set to 'FALSE' to disable.
   *
   * @param string|bool $reportUri
   *   A URI.
   *
   * @deprecated in 8.x-1.0-beta2, will be removed before 8.x-1.0. Use
   * setDirective('report-uri') instead.
   */
  public function setReportUri($reportUri) {
    $this->setDirective('report-uri', $reportUri);
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
