<?php

namespace Drupal\csp;

use Drupal\Component\Utility\NestedArray;
use Drupal\Core\Asset\LibraryDiscoveryInterface;
use Drupal\Core\Cache\Cache;
use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Theme\ThemeManagerInterface;
use GuzzleHttp\Psr7\Uri;

/**
 * Service to build policy information for libraries.
 */
class LibraryPolicyBuilder {

  /**
   * The Library Discovery service.
   *
   * @var \Drupal\Core\Asset\LibraryDiscovery
   */
  protected $libraryDiscovery;

  /**
   * The cache bin.
   *
   * @var \Drupal\Core\Cache\CacheBackendInterface
   */
  protected $cache;

  /**
   * The module handler service.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  protected $moduleHandler;

  /**
   * The Theme Manager service.
   *
   * @var \Drupal\Core\Theme\ThemeManagerInterface
   */
  protected $themeManager;

  /**
   * Constructs a new Library Parser.
   *
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache
   *   The cache bin.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The Module Handler service.
   * @param \Drupal\Core\Theme\ThemeManagerInterface $themeManager
   *   The Theme Handler service.
   * @param \Drupal\Core\Asset\LibraryDiscoveryInterface $libraryDiscovery
   *   The Library Discovery Collector service.
   */
  public function __construct(
    CacheBackendInterface $cache,
    ModuleHandlerInterface $moduleHandler,
    ThemeManagerInterface $themeManager,
    LibraryDiscoveryInterface $libraryDiscovery
  ) {
    $this->cache = $cache;
    $this->moduleHandler = $moduleHandler;
    $this->themeManager = $themeManager;
    $this->libraryDiscovery = $libraryDiscovery;
  }

  /**
   * Retrieve all sources required for the active theme.
   *
   * @return array
   *   An array of sources keyed by type.
   */
  public function getSourcesForActiveTheme() {
    $cid = implode(':', [
      'csp',
      'active-theme',
      $this->themeManager->getActiveTheme()->getName(),
    ]);

    if (($cacheItem = $this->cache->get($cid))) {
      return $cacheItem->data;
    }

    $extensions = array_keys($this->moduleHandler->getModuleList());
    $extensions[] = $this->themeManager->getActiveTheme()->getName();
    $extensions[] = 'core';

    $sources = [
      'script-src' => [],
      'style-src' => [],
    ];

    foreach ($extensions as $extensionName) {
      $extensionSources = $this->getExtensionSources($extensionName);
      $sources = NestedArray::mergeDeep($sources, $extensionSources);
    }

    foreach (array_keys($sources) as $type) {
      sort($sources[$type]);
      $sources[$type] = array_unique($sources[$type]);
    }

    $this->cache->set($cid, $sources, Cache::PERMANENT, [
      'library_info',
      'config:core.extension',
    ]);

    return $sources;
  }

  /**
   * Get the required sources for an extension.
   *
   * @param string $extension
   *   The name of the extension that registered a library.
   *
   * @return array
   *   An array of sources keyed by type.
   */
  protected function getExtensionSources($extension) {
    $cid = implode(':', ['csp', 'extension', $extension]);

    $cacheItem = $this->cache->get($cid);
    if ($cacheItem) {
      return $cacheItem->data;
    }

    $sources = [
      'script-src' => [],
      'style-src' => [],
    ];

    $moduleLibraries = $this->libraryDiscovery->getLibrariesByExtension($extension);

    foreach ($moduleLibraries as $libraryName => $libraryInfo) {
      $librarySources = $this->getLibrarySources($extension, $libraryName);
      $sources = NestedArray::mergeDeep($sources, $librarySources);
    }

    $this->cache->set($cid, $sources, Cache::PERMANENT, [
      'library_info',
    ]);

    return $sources;
  }

  /**
   * Get the required sources for a single library.
   *
   * @param string $extension
   *   The name of the extension that registered a library.
   * @param string $name
   *   The name of a registered library to retrieve.
   *
   * @return array
   *   An array of sources keyed by type.
   */
  protected function getLibrarySources($extension, $name) {
    $cid = implode(':', ['csp', 'library', $extension, $name]);

    $cacheItem = $this->cache->get($cid);
    if ($cacheItem) {
      return $cacheItem->data;
    }

    $libraryInfo = $this->libraryDiscovery->getLibraryByName($extension, $name);
    $sources = [
      'script-src' => [],
      'style-src' => [],
    ];

    foreach ($libraryInfo['js'] as $jsInfo) {
      if ($jsInfo['type'] == 'external') {
        $sources['script-src'][] = self::getHostFromUri($jsInfo['data']);
      }
    }
    foreach ($libraryInfo['css'] as $cssInfo) {
      if ($cssInfo['type'] == 'external') {
        $sources['style-src'][] = self::getHostFromUri($cssInfo['data']);
      }
    }

    $this->cache->set($cid, $sources, Cache::PERMANENT, [
      'library_info',
    ]);

    return $sources;
  }

  /**
   * Get host info from a URI.
   *
   * @param string $uri
   *   The URI.
   *
   * @return string
   *   The host info.
   */
  public static function getHostFromUri($uri) {
    $uri = new Uri($uri);
    $host = $uri->getHost();

    // Only include scheme if restricted to HTTPS.
    if ($uri->getScheme() === 'https') {
      $host = 'https://' . $host;
    }
    if (($port = $uri->getPort())) {
      $host .= ':' . $port;
    }
    return $host;
  }

}
