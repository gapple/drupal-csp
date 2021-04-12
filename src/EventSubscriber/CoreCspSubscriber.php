<?php

namespace Drupal\csp\EventSubscriber;

use Drupal\Core\Asset\LibraryDependencyResolverInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Render\AttachmentsInterface;
use Drupal\csp\Csp;
use Drupal\csp\CspEvents;
use Drupal\csp\Event\PolicyAlterEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Alter CSP policy for core modules and themes.
 */
class CoreCspSubscriber implements EventSubscriberInterface {

  /**
   * The Library Dependency Resolver service.
   *
   * @var \Drupal\Core\Asset\LibraryDependencyResolverInterface
   */
  private $libraryDependencyResolver;

  /**
   * The Module Handler service.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  private $moduleHandler;

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[CspEvents::POLICY_ALTER] = ['onCspPolicyAlter'];
    return $events;
  }

  /**
   * CoreCspSubscriber constructor.
   *
   * @param \Drupal\Core\Asset\LibraryDependencyResolverInterface $libraryDependencyResolver
   *   The Library Dependency Resolver Service.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The Module Handler service.
   */
  public function __construct(LibraryDependencyResolverInterface $libraryDependencyResolver, ModuleHandlerInterface $moduleHandler) {
    $this->libraryDependencyResolver = $libraryDependencyResolver;
    $this->moduleHandler = $moduleHandler;
  }

  /**
   * Alter CSP policy for libraries included in Drupal core.
   *
   * @param \Drupal\csp\Event\PolicyAlterEvent $alterEvent
   *   The Policy Alter event.
   */
  public function onCspPolicyAlter(PolicyAlterEvent $alterEvent) {
    $policy = $alterEvent->getPolicy();
    $response = $alterEvent->getResponse();

    if ($response instanceof AttachmentsInterface) {
      $attachments = $response->getAttachments();
      $libraries = isset($attachments['library']) ?
        $this->libraryDependencyResolver->getLibrariesWithDependencies($attachments['library']) :
        [];

      // Ajax needs 'unsafe-inline' to add assets required by responses.
      // @see https://www.drupal.org/project/csp/issues/3100084
      // The CSP Extras module alters core to not require 'unsafe-inline'.
      if (in_array('core/drupal.ajax', $libraries) && !$this->moduleHandler->moduleExists('csp_extras')) {
        // Prevent script-src-attr from falling back to script-src and having
        // 'unsafe-inline' enabled.
        $policy->fallbackAwareAppendIfEnabled('script-src-attr', []);
        $policy->fallbackAwareAppendIfEnabled('script-src', [Csp::POLICY_UNSAFE_INLINE]);
        $policy->fallbackAwareAppendIfEnabled('script-src-elem', [Csp::POLICY_UNSAFE_INLINE]);

        $policy->fallbackAwareAppendIfEnabled('style-src-attr', []);
        $policy->fallbackAwareAppendIfEnabled('style-src', [Csp::POLICY_UNSAFE_INLINE]);
        $policy->fallbackAwareAppendIfEnabled('style-src-elem', [Csp::POLICY_UNSAFE_INLINE]);
      }

      // Quickedit loads ckeditor after an AJAX request, so alter needs to be
      // applied to calling page.
      $quickedit = in_array('quickedit/quickedit', $libraries) && $this->moduleHandler->moduleExists('ckeditor');

      // CKEditor requires script attribute on interface buttons.
      if (in_array('core/ckeditor', $libraries) || $quickedit) {
        $policy->fallbackAwareAppendIfEnabled('script-src-elem', []);
        $policy->fallbackAwareAppendIfEnabled('script-src', [Csp::POLICY_UNSAFE_INLINE]);
        $policy->fallbackAwareAppendIfEnabled('script-src-attr', [Csp::POLICY_UNSAFE_INLINE]);
      }

      // Inline style element is added by ckeditor.off-canvas-css-reset.js.
      // @see https://www.drupal.org/project/drupal/issues/2952390
      if (in_array('ckeditor/drupal.ckeditor', $libraries) || $quickedit) {
        $policy->fallbackAwareAppendIfEnabled('style-src', [Csp::POLICY_UNSAFE_INLINE]);
        $policy->fallbackAwareAppendIfEnabled('style-src-attr', [Csp::POLICY_UNSAFE_INLINE]);
        $policy->fallbackAwareAppendIfEnabled('style-src-elem', [Csp::POLICY_UNSAFE_INLINE]);
      }

      $umamiFontLibraries = [
        // <= 8.7
        'umami/webfonts',
        // >= 8.8
        'umami/webfonts-open-sans',
        'umami/webfonts-scope-one',
      ];
      if (!empty(array_intersect($libraries, $umamiFontLibraries))) {
        $policy->fallbackAwareAppendIfEnabled('font-src', ['https://fonts.gstatic.com']);
      }
    }
  }

}
