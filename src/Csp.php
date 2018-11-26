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
  // 'sandbox' may have an empty value, or a set of tokens.
  const DIRECTIVE_SCHEMA_OPTIONAL_TOKEN_LIST = 'optional-token-list';
  const DIRECTIVE_SCHEMA_TOKEN = 'token';
  const DIRECTIVE_SCHEMA_URI_REFERENCE_LIST = 'uri-reference-list';
  const DIRECTIVE_SCHEMA_BOOLEAN = 'boolean';

  /**
   * The schema type for each directive.
   *
   * @var array
   */
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
    'sandbox' => self::DIRECTIVE_SCHEMA_OPTIONAL_TOKEN_LIST,
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
   * Fallback order for each directive.
   *
   * @var array
   *
   * @see https://www.w3.org/TR/CSP/#directive-fallback-list
   */
  private static $directiveFallbackList = [
    'script-src-elem' => ['script-src', 'default-src'],
    'script-src-attr' => ['script-src', 'default-src'],
    'script-src' => ['default-src'],
    'style-src-elem' => ['style-src', 'default-src'],
    'style-src-attr' => ['style-src', 'default-src'],
    'style-src' => ['default-src'],
    'worker-src' => ['child-src', 'script-src', 'default-src'],
    'child-src' => ['script-src', 'default-src'],
    'connect-src' => ['default-src'],
    'manifest-src' => ['default-src'],
    'prefetch-src' => ['default-src'],
    'object-src' => ['default-src'],
    'frame-src' => ['child-src', 'default-src'],
    'media-src' => ['default-src'],
    'font-src' => ['default-src'],
    'img-src' => ['default-src'],
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
   * Get the fallback list for a directive.
   *
   * @param string $name
   *   The directive name.
   *
   * @return array
   *   An ordered list of fallback directives.
   */
  public static function getDirectiveFallbackList($name) {
    if (!static::isValidDirectiveName($name)) {
      throw new \InvalidArgumentException("Invalid directive name provided");
    }

    if (array_key_exists($name, self::$directiveFallbackList)) {
      return self::$directiveFallbackList[$name];
    }

    return [];
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

    if (self::$directiveSchemaMap[$name] === self::DIRECTIVE_SCHEMA_BOOLEAN) {
      $this->directives[$name] = (bool) $value;
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

    $directives = $this->directives;

    $defaultSrc = '';
    if (isset($directives['default-src'])) {
      $defaultSrc = self::reduceSourceList($directives['default-src']);
      unset($directives['default-src']);
      $output[] = 'default-src ' . implode(' ', $defaultSrc);
    }

    foreach ($directives as $name => $value) {
      if (empty($value) && self::$directiveSchemaMap[$name] !== self::DIRECTIVE_SCHEMA_OPTIONAL_TOKEN_LIST) {
        continue;
      }

      if (
        self::$directiveSchemaMap[$name] === self::DIRECTIVE_SCHEMA_BOOLEAN
        ||
        self::$directiveSchemaMap[$name] === self::DIRECTIVE_SCHEMA_OPTIONAL_TOKEN_LIST && empty($value)
      ) {
        $output[] = $name;
        continue;
      }

      if (in_array(self::$directiveSchemaMap[$name], [
        self::DIRECTIVE_SCHEMA_SOURCE_LIST,
        self::DIRECTIVE_ANCESTOR_SOURCE_LIST,
      ])) {
        $value = self::reduceSourceList($value);
      }

      // Skip if directive inherits from default-src, and has same value.
      if (
        in_array('default-src', self::getDirectiveFallbackList($name))
        &&
        $value === $defaultSrc
      ) {
        continue;
      }

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

    // Global wildcard covers all network scheme sources.
    if (in_array('*', $sources)) {
      $sources = array_filter($sources, function ($source) {
        // Keep any values that are a quoted string, or non-network scheme.
        // e.g. '* https: data: example.com' -> 'data: *'
        // https://www.w3.org/TR/CSP/#match-url-to-source-expression
        return strpos($source, "'") === 0 || preg_match('<^(?!ftp|https?:)([a-z]+:)>', $source);
      });

      $sources[] = '*';

      return $sources;
    }

    return $sources;
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
