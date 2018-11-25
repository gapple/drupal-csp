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

  // https://www.w3.org/TR/CSP/#grammardef-serialized-source-list
  const DIRECTIVE_SCHEMA_SOURCE_LIST = 'serialized-source-list';
  // https://www.w3.org/TR/CSP/#grammardef-ancestor-source-list
  const DIRECTIVE_ANCESTOR_SOURCE_LIST = 'ancestor-source-list';
  // https://www.w3.org/TR/CSP/#grammardef-media-type-list
  const DIRECTIVE_SCHEMA_MEDIA_TYPE_LIST = 'media-type-list';
  const DIRECTIVE_SCHEMA_TOKEN_LIST = 'token-list';
  const DIRECTIVE_SCHEMA_TOKEN = 'token';
  const DIRECTIVE_SCHEMA_URI_REFERENCE_LIST = 'uri-reference-list';
  const DIRECTIVE_SCHEMA_BOOLEAN = 'boolean';

  private static $directiveSchemaMap = [
    // Fetch Directives.
    // @see https://www.w3.org/TR/CSP3/#directives-fetch
    'default-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'child-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'connect-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'font-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'frame-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'img-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'manifest-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'media-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'object-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'prefetch-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'script-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'style-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'worker-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    // Document Directives.
    // @see https://www.w3.org/TR/CSP3/#directives-document
    'base-uri' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'plugin-types' => self::DIRECTIVE_SCHEMA_MEDIA_TYPE_LIST,
    'sandbox' => self::DIRECTIVE_SCHEMA_TOKEN_LIST,
    // Navigation Directives.
    // @see https://www.w3.org/TR/CSP3/#directives-navigation
    'form-action' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'frame-ancestors' => self::DIRECTIVE_ANCESTOR_SOURCE_LIST,
    'navigate-to' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    // Reporting Directives.
    // @see https://www.w3.org/TR/CSP3/#directives-reporting
    'report-uri' => self::DIRECTIVE_SCHEMA_URI_REFERENCE_LIST,
    'report-to' => self::DIRECTIVE_SCHEMA_TOKEN,
    // Other directives.
    // @see https://www.w3.org/TR/CSP/#directives-elsewhere
    'block-all-mixed-content' => self::DIRECTIVE_SCHEMA_BOOLEAN,
    'require-sri-for' => self::DIRECTIVE_SCHEMA_TOKEN_LIST,
    'upgrade-insecure-requests' => self::DIRECTIVE_SCHEMA_BOOLEAN,
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
    return array_key_exists($name, static::$directiveSchemaMap);
  }

  /**
   * Get the valid directive names.
   *
   * @return array
   *   An array of directive names.
   */
  public static function getDirectiveNames() {
    return array_keys(self::$directiveSchemaMap);
  }

  /**
   * Add a new directive to the policy, or replace an existing directive.
   *
   * @param string $name
   *   The directive name.
   * @param array|bool|string $value
   *   The directive value.
   */
  public function setDirective($name, $value) {
    if (!static::isValidDirectiveName($name)) {
      throw new \InvalidArgumentException("Invalid directive name provided");
    }

    // TODO Validate that the specified directive is a boolean type.
    if (gettype($value) == 'boolean') {
      $this->directives[$name] = $value;
      return;
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

      if (gettype($value) == 'boolean') {
        $output[] = $name;
        continue;
      }

      if (in_array(self::$directiveSchemaMap[$name], [
        self::DIRECTIVE_SCHEMA_SOURCE_LIST,
        self::DIRECTIVE_ANCESTOR_SOURCE_LIST,
      ])) {
        $value = self::reduceSourceList($value);
      }
      // TODO Skip if directive inherits from default-src, and has same value.
      $output[] = $name . ' ' . implode(' ', $value);
    }

    return implode('; ', $output);
  }

  /**
   * Reduce a list of sources to a minimal set.
   *
   * @param array $sources
   *   The array of sources.
   *
   * @return array
   *   The reduced set of sources.
   */
  private static function reduceSourceList(array $sources) {
    $sources = array_unique($sources);

    // Global wildcard.
    // Wildcards and matching subdomains (*.example.com, sub.example.com)
    // Protocols (example.com, https://example.com)

    return $sources;
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
