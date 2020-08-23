<?php

namespace Drupal\csp\EventSubscriber;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\csp\Csp;
use Drupal\csp\CspEvents;
use Drupal\csp\Event\PolicyAlterEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Alter CSP policy for IE9 Compatibility.
 */
class Ie9CspSubscriber implements EventSubscriberInterface {

  /**
   * The Module Handler Service.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  private $moduleHandler;

  /**
   * The Config Factory Service.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  private $configFactory;

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[CspEvents::POLICY_ALTER] = ['onCspPolicyAlter'];
    return $events;
  }

  /**
   * Ie9CspSubscriber constructor.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The Config Factory service.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The Module Handler service.
   */
  public function __construct(ConfigFactoryInterface $configFactory, ModuleHandlerInterface $moduleHandler) {
    $this->configFactory = $configFactory;
    $this->moduleHandler = $moduleHandler;
  }

  /**
   * Alter CSP policy for compatibility with IE9 if needed.
   *
   * Prior to Drupal 8.7, in order to support IE9, CssCollectionRenderer
   * outputs more than 31 stylesheets as inline @import statements.
   * Since checking the actual number of stylesheets included on the page is
   * more difficult, just check the optimization settings, as in
   * HtmlResponseAttachmentsProcessor::processAssetLibraries()
   *
   * @param \Drupal\csp\Event\PolicyAlterEvent $alterEvent
   *   The Policy Alter event.
   *
   * @see https://www.drupal.org/node/2993171
   * @see CssCollectionRenderer::render()
   * @see HtmlResponseAttachmentsProcessor::processAssetLibraries()
   */
  public function onCspPolicyAlter(PolicyAlterEvent $alterEvent) {
    if (
      (
        version_compare(\Drupal::VERSION, '8.7', '<')
        ||
        $this->moduleHandler->moduleExists('ie9')
      )
      &&
      (
        defined('MAINTENANCE_MODE')
        ||
        !$this->configFactory->get('system.performance')->get('css.preprocess')
      )
    ) {
      $policy = $alterEvent->getPolicy();
      // Prevent style-src-attr from falling back to style-src and having
      // 'unsafe-inline' enabled.
      $policy->fallbackAwareAppendIfEnabled('style-src-attr', []);
      $policy->fallbackAwareAppendIfEnabled('style-src', [Csp::POLICY_UNSAFE_INLINE]);
      $policy->fallbackAwareAppendIfEnabled('style-src-elem', [Csp::POLICY_UNSAFE_INLINE]);
    }
  }

}
