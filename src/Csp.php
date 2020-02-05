<?php

namespace Drupal\csp;

/**
 * A CSP Header.
 */
class Csp {

  const HASH_ALGORITHMS = ['sha256', 'sha384', 'sha512'];

  const POLICY_ANY = "*";
  const POLICY_NONE = "'none'";
  const POLICY_SELF = "'self'";
  const POLICY_STRICT_DYNAMIC = "'strict-dynamic'";
  const POLICY_UNSAFE_EVAL = "'unsafe-eval'";
  const POLICY_UNSAFE_INLINE = "'unsafe-inline'";
  const POLICY_UNSAFE_HASHES = "'unsafe-hashes'";

  // https://www.w3.org/TR/CSP/#grammardef-serialized-source-list
  const DIRECTIVE_SCHEMA_SOURCE_LIST = 'serialized-source-list';
  // https://www.w3.org/TR/CSP/#grammardef-ancestor-source-list
  const DIRECTIVE_SCHEMA_ANCESTOR_SOURCE_LIST = 'ancestor-source-list';
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
  const DIRECTIVES = [
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
    'script-src-attr' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'script-src-elem' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'style-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'style-src-attr' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'style-src-elem' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'worker-src' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    // Document Directives.
    // @see https://www.w3.org/TR/CSP3/#directives-document
    'base-uri' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'plugin-types' => self::DIRECTIVE_SCHEMA_MEDIA_TYPE_LIST,
    'sandbox' => self::DIRECTIVE_SCHEMA_OPTIONAL_TOKEN_LIST,
    // Navigation Directives.
    // @see https://www.w3.org/TR/CSP3/#directives-navigation
    'form-action' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    'frame-ancestors' => self::DIRECTIVE_SCHEMA_ANCESTOR_SOURCE_LIST,
    'navigate-to' => self::DIRECTIVE_SCHEMA_SOURCE_LIST,
    // Reporting Directives.
    // @see https://www.w3.org/TR/CSP3/#directives-reporting
    'report-uri' => self::DIRECTIVE_SCHEMA_URI_REFERENCE_LIST,
    'report-to' => self::DIRECTIVE_SCHEMA_TOKEN,
    // Other directives.
    // @see https://www.w3.org/TR/CSP/#directives-elsewhere
    'block-all-mixed-content' => self::DIRECTIVE_SCHEMA_BOOLEAN,
    'upgrade-insecure-requests' => self::DIRECTIVE_SCHEMA_BOOLEAN,
    // Deprecated directives.
    // Referrer isn't in the Level 1 spec, but was accepted until Chrome 56 and
    // Firefox 62.
    'referrer' => self::DIRECTIVE_SCHEMA_TOKEN,
    // 'require-sri-for' was removed from the SRI spec.
    // @see https://www.drupal.org/project/csp/issues/3106728
    'require-sri-for' => self::DIRECTIVE_SCHEMA_TOKEN_LIST,
  ];

  /**
   * Fallback order for each directive.
   *
   * @var array
   *
   * @see https://www.w3.org/TR/CSP/#directive-fallback-list
   */
  const DIRECTIVES_FALLBACK = [
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
   * Calculate the Base64 encoded hash of a script.
   *
   * @param string $data
   *   The source data to hash.
   * @param string $algorithm
   *   The hash algorithm to use.
   *   Supported values are defined in \Drupal\csp\Csp::HASH_ALGORITHMS.
   *
   * @return string
   *   The hash value in the format <hash-algorithm>-<base64-value>
   */
  public static function calculateHash($data, $algorithm = 'sha256') {
    if (!in_array($algorithm, self::HASH_ALGORITHMS)) {
      throw new \InvalidArgumentException("Specified hash algorithm is not supported");
    }

    return $algorithm . '-' . base64_encode(hash($algorithm, $data, TRUE));
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
    return array_key_exists($name, static::DIRECTIVES);
  }

  /**
   * Check if a directive name is valid, throwing an exception if not.
   *
   * @param string $name
   *   The directive name.
   *
   * @throws \InvalidArgumentException
   */
  private static function validateDirectiveName($name) {
    if (!static::isValidDirectiveName($name)) {
      throw new \InvalidArgumentException("Invalid directive name provided");
    }
  }

  /**
   * Get the valid directive names.
   *
   * @return array
   *   An array of directive names.
   */
  public static function getDirectiveNames() {
    return array_keys(self::DIRECTIVES);
  }

  /**
   * Get the schema constant for a directive.
   *
   * @param string $name
   *   The directive name.
   *
   * @return string
   *   A DIRECTIVE_SCHEMA_* constant value
   */
  public static function getDirectiveSchema($name) {
    self::validateDirectiveName($name);

    return self::DIRECTIVES[$name];
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
    self::validateDirectiveName($name);

    if (array_key_exists($name, self::DIRECTIVES_FALLBACK)) {
      return self::DIRECTIVES_FALLBACK[$name];
    }

    return [];
  }

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
   * Retrieve whether this policy is report-only.
   *
   * @return bool
   *   The report-only status.
   */
  public function isReportOnly() {
    return $this->reportOnly;
  }

  /**
   * Check if the policy currently has the specified directive.
   *
   * @param string $name
   *   The directive name.
   *
   * @return bool
   *   If the policy has the specified directive.
   */
  public function hasDirective($name) {
    return isset($this->directives[$name]);
  }

  /**
   * Get the value of a directive.
   *
   * @param string $name
   *   The directive name.
   *
   * @return array
   *   The directive's values.
   */
  public function getDirective($name) {
    self::validateDirectiveName($name);

    return $this->directives[$name];
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
    self::validateDirectiveName($name);

    if (self::DIRECTIVES[$name] === self::DIRECTIVE_SCHEMA_BOOLEAN) {
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
    self::validateDirectiveName($name);

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
    self::validateDirectiveName($name);

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
    $optimizedDirectives = [];

    foreach ($this->directives as $name => $value) {
      if (empty($value) && self::DIRECTIVES[$name] !== self::DIRECTIVE_SCHEMA_OPTIONAL_TOKEN_LIST) {
        continue;
      }

      if (
        self::DIRECTIVES[$name] === self::DIRECTIVE_SCHEMA_BOOLEAN
        ||
        self::DIRECTIVES[$name] === self::DIRECTIVE_SCHEMA_OPTIONAL_TOKEN_LIST && empty($value)
      ) {
        $output[] = $name;
        continue;
      }

      if (in_array(self::DIRECTIVES[$name], [
        self::DIRECTIVE_SCHEMA_SOURCE_LIST,
        self::DIRECTIVE_SCHEMA_ANCESTOR_SOURCE_LIST,
      ])) {
        $value = self::reduceSourceList($value);
      }

      $optimizedDirectives[$name] = $value;
    }

    foreach ($optimizedDirectives as $name => $value) {
      foreach (self::getDirectiveFallbackList($name) as $fallbackDirective) {
        if (isset($optimizedDirectives[$fallbackDirective])) {
          if ($optimizedDirectives[$fallbackDirective] === $value) {
            // Omit directive if it matches nearest defined directive in its
            // fallback list.
            continue 2;
          }
          else {
            // If directive doesn't match nearest defined fallback, further
            // fallback directives must not be checked.
            break;
          }
        }
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

    // 'none' overrides any other sources.
    if (in_array(Csp::POLICY_NONE, $sources)) {
      return [Csp::POLICY_NONE];
    }

    // Global wildcard covers all network scheme sources.
    if (in_array(Csp::POLICY_ANY, $sources)) {
      $sources = array_filter($sources, function ($source) {
        // Keep any values that are a quoted string, or non-network scheme.
        // e.g. '* https: data: example.com' -> '* data:'
        // https://www.w3.org/TR/CSP/#match-url-to-source-expression
        return strpos($source, "'") === 0 || preg_match('<^(?!(?:https?|wss?|ftp):)([a-z]+:)>', $source);
      });

      array_unshift($sources, Csp::POLICY_ANY);
    }

    // Remove protocol-prefixed hosts if protocol is allowed.
    // e.g. 'http: data: example.com https://example.com' -> 'http: data: example.com'
    $protocols = array_filter($sources, function ($source) {
      return preg_match('<^(https?|wss?|ftp):$>', $source);
    });
    if (!empty($protocols)) {
      if (in_array('http:', $protocols)) {
        $protocols[] = 'https:';
      }
      if (in_array('ws:', $protocols)) {
        $protocols[] = 'wss:';
      }
      $sources = array_filter($sources, function ($source) use ($protocols) {
        return !preg_match('<^(' . implode('|', $protocols) . ')//>', $source);
      });
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
