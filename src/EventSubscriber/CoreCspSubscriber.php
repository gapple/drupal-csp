<?php

namespace Drupal\csp\EventSubscriber;

use Drupal\Core\Asset\LibraryDependencyResolverInterface;
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
  public function __construct(LibraryDependencyResolverInterface $libraryDependencyResolver) {
    $this->libraryDependencyResolver = $libraryDependencyResolver;
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
      if (in_array('core/drupal.ajax', $libraries)) {
        if ($policy->hasDirective('script-src')) {
          $policy->appendDirective('script-src', [Csp::POLICY_UNSAFE_INLINE]);
        }
        elseif ($policy->hasDirective('default-src')) {
          $scriptDirective = array_merge($policy->getDirective('default-src'), [Csp::POLICY_UNSAFE_INLINE]);
          $policy->setDirective('script-src', $scriptDirective);
        }

        if ($policy->hasDirective('script-src-elem')) {
          $policy->appendDirective('script-src-elem', [Csp::POLICY_UNSAFE_INLINE]);
        }
        elseif ($policy->hasDirective('script-src')) {
          $scriptDirective = array_merge($policy->getDirective('script-src'), [Csp::POLICY_UNSAFE_INLINE]);
          $policy->setDirective('script-src-elem', $scriptDirective);
        }
        // If default-src is set, script-src was already created above if
        // necessary, so no need to fallback further for script-src-elem.

        if ($policy->hasDirective('style-src')) {
          $policy->appendDirective('style-src', [Csp::POLICY_UNSAFE_INLINE]);
        }
        elseif ($policy->hasDirective('default-src')) {
          $scriptDirective = array_merge($policy->getDirective('default-src'), [Csp::POLICY_UNSAFE_INLINE]);
          $policy->setDirective('style-src', $scriptDirective);
        }

        if ($policy->hasDirective('style-src-elem')) {
          $policy->appendDirective('style-src-elem', [Csp::POLICY_UNSAFE_INLINE]);
        }
        elseif ($policy->hasDirective('style-src')) {
          $scriptDirective = array_merge($policy->getDirective('style-src'), [Csp::POLICY_UNSAFE_INLINE]);
          $policy->setDirective('script-src-elem', $scriptDirective);
        }
        // If default-src is set, style-src was already created above if
        // necessary, so no need to fallback further for style-src-elem.
      }

      // CKEditor requires script attribute on interface buttons.
      if (in_array('core/ckeditor', $libraries)) {
        if ($policy->hasDirective('script-src')) {
          $policy->appendDirective('script-src', [Csp::POLICY_UNSAFE_INLINE]);
        }
        elseif ($policy->hasDirective('default-src')) {
          $scriptDirective = array_merge($policy->getDirective('default-src'), [Csp::POLICY_UNSAFE_INLINE]);
          $policy->setDirective('script-src', $scriptDirective);
        }

        if ($policy->hasDirective('script-src-attr')) {
          $policy->appendDirective('script-src-attr', [Csp::POLICY_UNSAFE_INLINE]);
        }
        elseif ($policy->hasDirective('script-src')) {
          $scriptDirective = array_merge($policy->getDirective('script-src'), [Csp::POLICY_UNSAFE_INLINE]);
          $policy->setDirective('script-src-attr', $scriptDirective);
        }
        // If default-src is set, script-src was already created above if
        // necessary, so no need to fallback further for script-src-attr.
      }
      // Inline style element is added by ckeditor.off-canvas-css-reset.js.
      // @see https://www.drupal.org/project/drupal/issues/2952390
      if (in_array('ckeditor/drupal.ckeditor', $libraries)) {
        if ($policy->hasDirective('style-src')) {
          $policy->appendDirective('style-src', [Csp::POLICY_UNSAFE_INLINE]);
        }
        elseif ($policy->hasDirective('default-src')) {
          $scriptDirective = array_merge($policy->getDirective('default-src'), [Csp::POLICY_UNSAFE_INLINE]);
          $policy->setDirective('style-src', $scriptDirective);
        }

        if ($policy->hasDirective('style-src-elem')) {
          $policy->appendDirective('style-src-elem', [Csp::POLICY_UNSAFE_INLINE]);
        }
        elseif ($policy->hasDirective('style-src')) {
          $scriptDirective = array_merge($policy->getDirective('style-src'), [Csp::POLICY_UNSAFE_INLINE]);
          $policy->setDirective('style-src-elem', $scriptDirective);
        }
        // If default-src is set, style-src was already created above if
        // necessary, so no need to fallback further for style-src-elem.
      }

      $umamiFontLibraries = [
        // <= 8.7
        'umami/webfonts',
        // >= 8.8
        'umami/webfonts-open-sans',
        'umami/webfonts-scope-one',
      ];
      if (!empty(array_intersect($libraries, $umamiFontLibraries))) {
        if ($policy->hasDirective('font-src')) {
          $policy->appendDirective('font-src', ['https://fonts.gstatic.com']);
        }
        elseif ($policy->hasDirective('default-src')) {
          $fontDirective = array_merge($policy->getDirective('default-src'), ['https://fonts.gstatic.com']);
          $policy->appendDirective('font-src', $fontDirective);
        }
      }
    }
  }

}
