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
      if (in_array('core/drupal.ajax', $libraries)) {
        self::fallbackAwareAppendIfEnabled($policy, 'script-src', [Csp::POLICY_UNSAFE_INLINE]);
        self::fallbackAwareAppendIfEnabled($policy, 'script-src-elem', [Csp::POLICY_UNSAFE_INLINE]);

        self::fallbackAwareAppendIfEnabled($policy, 'style-src', [Csp::POLICY_UNSAFE_INLINE]);
        self::fallbackAwareAppendIfEnabled($policy, 'style-src-elem', [Csp::POLICY_UNSAFE_INLINE]);
      }

      // CKEditor requires script attribute on interface buttons.
      if (in_array('core/ckeditor', $libraries)) {
        self::fallbackAwareAppendIfEnabled($policy, 'script-src', [Csp::POLICY_UNSAFE_INLINE]);
        self::fallbackAwareAppendIfEnabled($policy, 'script-src-attr', [Csp::POLICY_UNSAFE_INLINE]);
      }
      // Quickedit loads ckeditor after an AJAX request, so alter needs to be
      // applied to calling page.
      if (in_array('quickedit/quickedit', $libraries) && $this->moduleHandler->moduleExists('ckeditor')) {
        self::fallbackAwareAppendIfEnabled($policy, 'script-src', [Csp::POLICY_UNSAFE_INLINE]);
        self::fallbackAwareAppendIfEnabled($policy, 'script-src-attr', [Csp::POLICY_UNSAFE_INLINE]);
      }

      // Inline style element is added by ckeditor.off-canvas-css-reset.js.
      // @see https://www.drupal.org/project/drupal/issues/2952390
      if (in_array('ckeditor/drupal.ckeditor', $libraries)) {
        self::fallbackAwareAppendIfEnabled($policy, 'style-src', [Csp::POLICY_UNSAFE_INLINE]);
        self::fallbackAwareAppendIfEnabled($policy, 'style-src-elem', [Csp::POLICY_UNSAFE_INLINE]);
      }

      $umamiFontLibraries = [
        // <= 8.7
        'umami/webfonts',
        // >= 8.8
        'umami/webfonts-open-sans',
        'umami/webfonts-scope-one',
      ];
      if (!empty(array_intersect($libraries, $umamiFontLibraries))) {
        self::fallbackAwareAppendIfEnabled($policy, 'font-src', ['https://fonts.gstatic.com']);
      }
    }
  }

  /**
   * Append to a directive if it or a fallback directive is enabled.
   *
   * If the specified directive is not enabled but one of its fallback
   * directives is, it will be initialized with the same value as the fallback
   * before appending the new value.
   *
   * If none of the specified directive's fallbacks are enabled, the directive
   * will not be enabled.
   *
   * @param \Drupal\csp\Csp $policy
   *   The CSP directive to alter.
   * @param string $directive
   *   The directive name.
   * @param array|string $value
   *   The directive value.
   */
  private static function fallbackAwareAppendIfEnabled(Csp $policy, $directive, $value) {
    if ($policy->hasDirective($directive)) {
      $policy->appendDirective($directive, $value);
      return;
    }

    // Duplicate the closest fallback directive with a value.
    foreach (Csp::getDirectiveFallbackList($directive) as $fallback) {
      if ($policy->hasDirective($fallback)) {
        $policy->setDirective($directive, $policy->getDirective($fallback));
        $policy->appendDirective($directive, $value);
        return;
      }
    }
  }

}
