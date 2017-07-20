<?php

namespace Drupal\csp\EventSubscriber;

use Drupal\Core\Config\ConfigFactoryInterface;
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
   * Constructs a new ResponseSubscriber object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   Config Factory service.
   */
  public function __construct(ConfigFactoryInterface $configFactory) {
    $this->configFactory = $configFactory;
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

    $policy = [
      'default-src' => "'self'",
    ];

    // IE9 only supports up to 31 stylesheets on the page, so if there are more
    // CssCollectionRenderer outputs them inline as @import statements instead.
    // Since checking the actual number of stylesheets included on the page is
    // more difficult, we'll just check the optimization settings, as in
    // HtmlResponseAttachmentsProcessor::processAssetLibraries()
    // @see CssCollectionRenderer::render()
    // @see HtmlResponseAttachmentsProcessor::processAssetLibraries()
    if (defined('MAINTENANCE_MODE') || !$this->configFactory->get('system.performance')->get('css.preprocess')) {
      $policy['style-src'] = "'self' 'unsafe-inline'";
    }

    $response->headers->set(
      'Content-Security-Policy-Report-Only',
      implode('; ', array_map(function ($key, $value) {
        return $key . ' ' . $value;
      }, array_keys($policy), $policy))
    );
  }

}
