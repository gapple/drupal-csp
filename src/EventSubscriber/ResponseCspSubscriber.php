<?php

namespace Drupal\csp\EventSubscriber;

use Drupal\Core\Asset\LibraryDiscovery;
use Drupal\Core\Cache\Cache;
use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
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
   * Arrays of hosts, keyed by resource type.
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
   *   The Module Handler Interface.
   * @param \Drupal\Core\Asset\LibraryDiscovery $libraryDiscovery
   *   The Library Discovery Collector service.
   */
  public function __construct(
    ConfigFactoryInterface $configFactory,
    CacheBackendInterface $cache,
    ModuleHandlerInterface $moduleHandler,
    LibraryDiscovery $libraryDiscovery
  ) {
    $this->configFactory = $configFactory;
    $this->cache = $cache;
    $this->moduleHandler = $moduleHandler;
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

    $response = $event->getResponse();

    $policy = new Csp();
    $policy->reportOnly(TRUE);

    $policy->setDirective('script-src', [Csp::POLICY_SELF]);
    if (($scriptHosts = $this->getHosts('script'))) {
      $policy->appendDirective('script-src', $scriptHosts);
    }
    $policy->setDirective('style-src', [Csp::POLICY_SELF]);
    if (($styleHosts = $this->getHosts('style'))) {
      $policy->appendDirective('style-src', $styleHosts);
    }

    // Prior to Drupal 8.5, in order to support IE9, CssCollectionRenderer
    // outputs more than 31 stylesheets as inline @import statements.
    // @see https://www.drupal.org/node/2897408
    // Since checking the actual number of stylesheets included on the page is
    // more difficult, just check the optimization settings, as in
    // HtmlResponseAttachmentsProcessor::processAssetLibraries()
    // @see CssCollectionRenderer::render()
    // @see HtmlResponseAttachmentsProcessor::processAssetLibraries()
    if ((
        version_compare(\Drupal::VERSION, '8.5', '<')
        || $this->moduleHandler->moduleExists('ie9')
      ) && (
        defined('MAINTENANCE_MODE')
        || !$this->configFactory->get('system.performance')->get('css.preprocess')
    )) {
      $policy->appendDirective('style-src', [Csp::POLICY_UNSAFE_INLINE]);
    }

    $response->headers->set($policy->getHeaderName(), $policy->getHeaderValue());
  }

  /**
   * Retrieve and cache hosts from library definitions.
   */
  protected function parseLibraryHosts() {
    $moduleList = $this->moduleHandler->getModuleList();

    $scriptHosts = [];
    $styleHosts = [];

    foreach ($moduleList as $extensionName => $extensionInfo) {
      $moduleLibraries = $this->libraryDiscovery->getLibrariesByExtension($extensionName);

      foreach ($moduleLibraries as $libraryName => $libraryInfo) {
        foreach ($libraryInfo['js'] as $jsInfo) {
          if ($jsInfo['type'] == 'external') {
            $scriptHosts[] = $this->getHostFromUri($jsInfo['data']);
          }
        }
        foreach ($libraryInfo['css'] as $cssInfo) {
          if ($cssInfo['type'] == 'external') {
            $styleHosts[] = $this->getHostFromUri($cssInfo['data']);
          }
        }
      }
    }

    sort($scriptHosts);
    sort($styleHosts);

    $this->setHosts('script', array_unique($scriptHosts));
    $this->setHosts('style', array_unique($styleHosts));
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
    $this->hosts[$type] = $hosts;

    $this->cache->set('csp:hosts:' . $type, $hosts, Cache::PERMANENT, ['library_info']);
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

    if (!isset($this->hosts[$type])) {
      $cacheData = $this->cache->get('csp:hosts:' . $type);

      if ($cacheData) {
        $this->hosts[$type] = $cacheData->data;
      }
    }

    if (!isset($this->hosts[$type])) {
      $this->parseLibraryHosts();
    }

    if (!isset($this->hosts[$type])) {
      throw new \Exception("Host type not available.");
    }

    return $this->hosts[$type];
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
