<?php

namespace Drupal\csp\EventSubscriber;

use Drupal\Core\Asset\LibraryDiscoveryInterface;
use Drupal\Core\Cache\Cache;
use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Theme\ThemeManagerInterface;
use Drupal\Core\Url;
use Drupal\csp\Csp;
use GuzzleHttp\Psr7\Uri;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Class ResponseSubscriber.
 */
class ResponseCspSubscriber implements EventSubscriberInterface {

  /**
   * The Config Factory service.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

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
   * Arrays of hosts, keyed by theme name and resource type.
   *
   * @var array
   */
  protected $hosts;

  /**
   * Constructs a new ResponseSubscriber object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   Config Factory service.
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
    ConfigFactoryInterface $configFactory,
    CacheBackendInterface $cache,
    ModuleHandlerInterface $moduleHandler,
    ThemeManagerInterface $themeManager,
    LibraryDiscoveryInterface $libraryDiscovery
  ) {
    $this->configFactory = $configFactory;
    $this->cache = $cache;
    $this->moduleHandler = $moduleHandler;
    $this->themeManager = $themeManager;
    $this->libraryDiscovery = $libraryDiscovery;
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[KernelEvents::RESPONSE] = ['onKernelResponse'];
    return $events;
  }

  /**
   * Add Content-Security-Policy header to response.
   *
   * @param \Symfony\Component\HttpKernel\Event\FilterResponseEvent $event
   *   The Response event.
   */
  public function onKernelResponse(FilterResponseEvent $event) {
    if (!$event->isMasterRequest()) {
      return;
    }

    $cspConfig = $this->configFactory->get('csp.settings');

    $response = $event->getResponse();

    $policy = new Csp();
    $policy->reportOnly(!$cspConfig->get('enforce'));

    $policy->setDirective('script-src', [Csp::POLICY_SELF]);
    if (($scriptHosts = $this->getHosts('script'))) {
      $policy->appendDirective('script-src', $scriptHosts);
    }
    $policy->setDirective('style-src', [Csp::POLICY_SELF]);
    if (($styleHosts = $this->getHosts('style'))) {
      $policy->appendDirective('style-src', $styleHosts);
    }

    // Prior to Drupal 8.6, in order to support IE9, CssCollectionRenderer
    // outputs more than 31 stylesheets as inline @import statements.
    // @see https://www.drupal.org/node/2897408
    // Since checking the actual number of stylesheets included on the page is
    // more difficult, just check the optimization settings, as in
    // HtmlResponseAttachmentsProcessor::processAssetLibraries()
    // @see CssCollectionRenderer::render()
    // @see HtmlResponseAttachmentsProcessor::processAssetLibraries()
    if ((
        version_compare(\Drupal::VERSION, '8.6', '<')
        || $this->moduleHandler->moduleExists('ie9')
      ) && (
        defined('MAINTENANCE_MODE')
        || !$this->configFactory->get('system.performance')->get('css.preprocess')
    )) {
      $policy->appendDirective('style-src', [Csp::POLICY_UNSAFE_INLINE]);
    }

    $reportHandler = $cspConfig->get('report.handler');
    if ($reportHandler == 'csp-module') {
      $reportUri = Url::fromRoute('csp.reporturi',
        [
          'type' => $cspConfig->get('enforce') ? 'enforce' : 'reportOnly',
        ],
        [
          'absolute' => TRUE,
        ]);
      $policy->setDirective('report-uri', $reportUri->toString());
    }
    elseif ($reportHandler == 'report-uri-com') {
      $reportUri = 'https://' . $cspConfig->get('report.options.subdomain') . '.report-uri.com/r/d/csp/' . ($cspConfig->get('enforce') ? 'enforce' : 'reportOnly');
      $policy->setDirective('report-uri', $reportUri);
    }
    elseif ($reportHandler == 'uri') {
      $policy->setDirective('report-uri', $cspConfig->get('report.options.uri'));
    }

    $response->headers->set($policy->getHeaderName(), $policy->getHeaderValue());
  }

  /**
   * Retrieve and cache hosts from library definitions.
   */
  protected function parseLibraryHosts() {
    $extensions = array_keys($this->moduleHandler->getModuleList());
    $extensions[] = $this->themeManager->getActiveTheme()->getName();
    $extensions[] = 'core';

    $hosts = [
      'script' => [],
      'style' => [],
    ];

    foreach ($extensions as $extensionName) {
      $moduleLibraries = $this->libraryDiscovery->getLibrariesByExtension($extensionName);

      foreach ($moduleLibraries as $libraryName => $libraryInfo) {
        foreach ($libraryInfo['js'] as $jsInfo) {
          if ($jsInfo['type'] == 'external') {
            $hosts['script'][] = $this->getHostFromUri($jsInfo['data']);
          }
        }
        foreach ($libraryInfo['css'] as $cssInfo) {
          if ($cssInfo['type'] == 'external') {
            $hosts['style'][] = $this->getHostFromUri($cssInfo['data']);
          }
        }
      }
    }

    foreach (array_keys($hosts) as $type) {
      sort($hosts[$type]);
      $this->setHosts($type, array_unique($hosts[$type]));
    }
  }

  /**
   * Cache a set of hosts by resource type.
   *
   * @param string $type
   *   The resource type, 'script' or 'style'.
   * @param array $hosts
   *   An array of hosts.
   */
  protected function setHosts($type, array $hosts) {
    $theme = $this->themeManager->getActiveTheme()->getName();

    $cid = implode(':', [
      'csp',
      'hosts',
      $theme,
      $type,
    ]);

    $this->hosts[$theme][$type] = $hosts;

    $this->cache->set($cid, $hosts, Cache::PERMANENT, ['library_info']);
  }

  /**
   * Retrieve a set of hosts by resource type.
   *
   * @param string $type
   *   The resource type, 'script' or 'style'.
   *
   * @return array
   *   An array of hosts.
   *
   * @throws \Exception
   */
  protected function getHosts($type) {
    $theme = $this->themeManager->getActiveTheme()->getName();

    $cid = implode(':', [
      'csp',
      'hosts',
      $theme,
      $type,
    ]);

    if (!isset($this->hosts[$theme][$type])) {
      $cacheData = $this->cache->get($cid);

      if ($cacheData) {
        $this->hosts[$theme][$type] = $cacheData->data;
      }
    }

    if (!isset($this->hosts[$theme][$type])) {
      $this->parseLibraryHosts();
    }

    if (!isset($this->hosts[$theme][$type])) {
      throw new \Exception("Host type not available.");
    }

    return $this->hosts[$theme][$type];
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
  protected function getHostFromUri($uri) {
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
