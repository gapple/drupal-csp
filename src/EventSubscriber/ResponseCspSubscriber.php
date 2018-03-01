<?php

namespace Drupal\csp\EventSubscriber;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Url;
use Drupal\csp\Csp;
use Drupal\csp\LibraryPolicyBuilder;
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
   * The module handler service.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  protected $moduleHandler;

  /**
   * The Library Policy Builder service.
   *
   * @var \Drupal\csp\LibraryPolicyBuilder
   */
  protected $libraryPolicyBuilder;

  /**
   * Constructs a new ResponseSubscriber object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   Config Factory service.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The Module Handler service.
   * @param \Drupal\csp\LibraryPolicyBuilder $libraryPolicyBuilder
   *   The Library Parser service.
   */
  public function __construct(
    ConfigFactoryInterface $configFactory,
    ModuleHandlerInterface $moduleHandler,
    LibraryPolicyBuilder $libraryPolicyBuilder
  ) {
    $this->configFactory = $configFactory;
    $this->moduleHandler = $moduleHandler;
    $this->libraryPolicyBuilder = $libraryPolicyBuilder;
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

    foreach (['report-only', 'enforce'] as $policyType) {

      if (!$cspConfig->get($policyType . '.enable')) {
        continue;
      }

      $policy = new Csp();
      $policy->reportOnly($policyType == 'report-only');

      foreach ($cspConfig->get($policyType . '.directives') as $directiveName => $directiveOptions) {

        if (is_bool($directiveOptions)) {
          $policy->setDirective($directiveName, TRUE);
          continue;
        }

        // This is a directive with a simple array of values.
        if (!isset($directiveOptions['base'])) {
          $policy->setDirective($directiveName, $directiveOptions);
          continue;
        }

        switch ($directiveOptions['base']) {
          case 'self':
            $policy->setDirective($directiveName, "'self'");
            break;

          case 'none':
            $policy->setDirective($directiveName, "'none'");
            break;

          case 'any':
            $policy->setDirective($directiveName, "*");
            break;
        }

        if (!empty($directiveOptions['flags'])) {
          $policy->appendDirective($directiveName, array_map(function ($value) {
            return "'" . $value . "'";
          }, $directiveOptions['flags']));
        }

        if (!empty($directiveOptions['sources'])) {
          $policy->appendDirective($directiveName, $directiveOptions['sources']);
        }
      }

      foreach ($this->libraryPolicyBuilder->getSources() as $directiveName => $sources) {
        $policy->appendDirective($directiveName, $sources);
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
          || !$this->configFactory->get('system.performance')
            ->get('css.preprocess')
        )) {
        $policy->appendDirective('style-src', [Csp::POLICY_UNSAFE_INLINE]);
      }

      $reportHandler = $cspConfig->get('report.handler');
      if ($reportHandler == 'csp-module') {
        $reportUri = Url::fromRoute(
          'csp.reporturi',
          ['type' => ($policyType == 'enforce') ? 'enforce' : 'reportOnly'],
          ['absolute' => TRUE]
        );
        $policy->setDirective('report-uri', $reportUri->toString());
      }
      elseif ($reportHandler == 'report-uri-com') {
        $reportUri = 'https://' . $cspConfig->get('report.options.subdomain') . '.report-uri.com/r/d/csp/' . (($policyType == 'enforce') ? 'enforce' : 'reportOnly');
        $policy->setDirective('report-uri', $reportUri);
      }
      elseif ($reportHandler == 'uri') {
        $policy->setDirective('report-uri', $cspConfig->get('report.options.uri'));
      }

      $response->headers->set($policy->getHeaderName(), $policy->getHeaderValue());
    }
  }

}
