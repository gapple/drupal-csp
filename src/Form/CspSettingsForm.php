<?php

namespace Drupal\csp\Form;

use Drupal\Component\Plugin\Exception\PluginException;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\csp\Csp;
use Drupal\csp\LibraryPolicyBuilder;
use Drupal\csp\ReportingHandlerPluginManager;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Form for editing Content Security Policy module settings.
 */
class CspSettingsForm extends ConfigFormBase {

  /**
   * The Library Policy Builder service.
   *
   * @var \Drupal\csp\LibraryPolicyBuilder
   */
  private $libraryPolicyBuilder;

  /**
   * The Reporting Handler Plugin Manager service.
   *
   * @var \Drupal\csp\ReportingHandlerPluginManager
   */
  private $reportingHandlerPluginManager;

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'csp_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [
      'csp.settings',
    ];
  }

  /**
   * Constructs a \Drupal\csp\Form\CspSettingsForm object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The factory for configuration objects.
   * @param \Drupal\csp\LibraryPolicyBuilder $libraryPolicyBuilder
   *   The Library Policy Builder service.
   * @param \Drupal\csp\ReportingHandlerPluginManager $reportingHandlerPluginManager
   *   The Reporting Handler Plugin Manger service.
   * @param \Drupal\Core\Messenger\MessengerInterface|null $messenger
   *   The Messenger service.
   */
  public function __construct(ConfigFactoryInterface $config_factory, LibraryPolicyBuilder $libraryPolicyBuilder, ReportingHandlerPluginManager $reportingHandlerPluginManager, MessengerInterface $messenger) {
    parent::__construct($config_factory);
    $this->libraryPolicyBuilder = $libraryPolicyBuilder;
    $this->reportingHandlerPluginManager = $reportingHandlerPluginManager;
    $this->setMessenger($messenger);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('config.factory'),
      $container->get('csp.library_policy_builder'),
      $container->get('plugin.manager.csp_reporting_handler'),
      $container->get('messenger')
    );
  }

  /**
   * Get the directives that should be configurable.
   *
   * @return array
   *   An array of directive names.
   */
  private function getConfigurableDirectives() {
    // Exclude some directives
    // - Reporting directives have dedicated fields elsewhere in the form.
    // - 'referrer' is deprecated in favour of the Referrer-Policy header, and
    //   not supported in most browsers.
    $directives = array_diff(
      Csp::getDirectiveNames(),
      ['report-uri', 'report-to', 'referrer']
    );

    return $directives;
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('csp.settings');
    // Script and Style must always be enabled.
    $autoDirectives = $this->libraryPolicyBuilder->getSources() + [
      'script-src' => [],
      'style-src' => [],
    ];

    $form['#attached']['library'][] = 'csp/admin';

    $form['report'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Reporting'),
      '#tree' => TRUE,
    ];
    $form['report']['handler'] = [
      '#type' => 'radios',
      '#title' => $this->t('Handler'),
      '#options' => [],
      '#default_value' => $config->get('report.plugin'),
    ];

    $reportingHandlerPluginDefinitions = $this->reportingHandlerPluginManager->getDefinitions();
    foreach ($reportingHandlerPluginDefinitions as $reportingHandlerPluginDefinition) {
      try {
        $reportingHandlerPlugin = $this->reportingHandlerPluginManager->createInstance(
          $reportingHandlerPluginDefinition['id'],
          ($config->get('report.plugin') == $reportingHandlerPluginDefinition['id']) ?
            ($config->get('report.options') ?: []) : []
        );
      }
      catch (PluginException $e) {
        watchdog_exception('csp', $e);
        continue;
      }

      $form['report']['handler']['#options'][$reportingHandlerPluginDefinition['id']] = $reportingHandlerPluginDefinition['label'];

      $form['report'][$reportingHandlerPluginDefinition['id']] = $reportingHandlerPlugin->getForm([
        '#type' => 'item',
        '#description' => $reportingHandlerPluginDefinition['description'],
        '#states' => [
          'visible' => [
            ':input[name="report[handler]"]' => ['value' => $reportingHandlerPluginDefinition['id']],
          ],
        ],
        '#CspReportingHandlerPlugin' => $reportingHandlerPlugin,
      ]);
    }

    $form['policies'] = [
      '#type' => 'vertical_tabs',
      '#title' => $this->t('Policies'),
    ];

    $directiveNames = $this->getConfigurableDirectives();
    $enforceOnlyDirectives = [
      // @see https://w3c.github.io/webappsec-upgrade-insecure-requests/#delivery
      'upgrade-insecure-requests',
      // @see https://www.w3.org/TR/CSP/#directive-sandbox
      'sandbox',
    ];

    $policyTypes = [
      'report-only' => $this->t('Report Only'),
      'enforce' => $this->t('Enforced'),
    ];
    foreach ($policyTypes as $policyTypeKey => $policyTypeName) {
      $form[$policyTypeKey] = [
        '#type' => 'details',
        '#title' => $policyTypeName,
        '#group' => 'policies',
        '#tree' => TRUE,
      ];

      if ($config->get($policyTypeKey . '.enable')) {
        $form['policies']['#default_tab'] = 'edit-' . $policyTypeKey;
      }

      $form[$policyTypeKey]['enable'] = [
        '#type' => 'checkbox',
        '#title' => $this->t("Enable '@type'", ['@type' => $policyTypeName]),
        '#default_value' => $config->get($policyTypeKey . '.enable'),
      ];

      $form[$policyTypeKey]['directives'] = [
        '#type' => 'fieldset',
        '#title' => $this->t('Directives'),
        '#description_display' => 'before',
        '#tree' => TRUE,
        '#states' => [
          'visible' => [
            ':input[name="' . $policyTypeKey . '[enable]"]' => ['checked' => TRUE],
          ],
        ],
      ];

      foreach ($directiveNames as $directiveName) {
        if ($policyTypeKey !== 'enforce' && in_array($directiveName, $enforceOnlyDirectives)) {
          continue;
        }

        $directiveSchema = Csp::getDirectiveSchema($directiveName);

        $form[$policyTypeKey]['directives'][$directiveName] = [
          '#type' => 'container',
        ];

        $forceEnable = isset($autoDirectives[$directiveName]);

        $form[$policyTypeKey]['directives'][$directiveName]['enable'] = [
          '#type' => 'checkbox',
          '#title' => $directiveName,
          '#default_value' => (
            $forceEnable
            // Csp::DIRECTIVE_SCHEMA_OPTIONAL_TOKEN_LIST may be an empty array,
            // so is_null() must be used instead of empty().
            // Directives which cannot be empty should not be present in config.
            // (e.g. boolean directives should only be present if TRUE).
            || !is_null($config->get($policyTypeKey . '.directives.' . $directiveName))
          ),
          '#disabled' => $forceEnable,
        ];
        $form[$policyTypeKey]['directives'][$directiveName]['options'] = [
          '#type' => 'container',
          '#states' => [
            'visible' => [
              ':input[name="' . $policyTypeKey . '[directives][' . $directiveName . '][enable]"]' => ['checked' => TRUE],
            ],
          ],
        ];

        if (!in_array($directiveSchema, [
          Csp::DIRECTIVE_SCHEMA_SOURCE_LIST,
          Csp::DIRECTIVE_SCHEMA_ANCESTOR_SOURCE_LIST,
        ])) {
          continue;
        }

        $sourceListBase = $config->get($policyTypeKey . '.directives.' . $directiveName . '.base');
        $form[$policyTypeKey]['directives'][$directiveName]['options']['base'] = [
          '#type' => 'radios',
          '#parents' => [$policyTypeKey, 'directives', $directiveName, 'base'],
          '#options' => [
            'self' => "Self",
            'none' => "None",
            'any' => "Any",
            '' => '<em>n/a</em>',
          ],
          '#default_value' => $sourceListBase !== NULL ? $sourceListBase : 'self',
        ];
        // Auto sources make a directive required, so remove the 'none' option.
        if ($forceEnable) {
          unset($form[$policyTypeKey]['directives'][$directiveName]['options']['base']['#options']['none']);
        }

        // Some directives do not support unsafe flags.
        // @see https://www.w3.org/TR/CSP/#grammardef-ancestor-source-list
        if ($directiveSchema == Csp::DIRECTIVE_SCHEMA_SOURCE_LIST) {
          // States currently don't work on checkboxes elements, so need to be
          // applied to a wrapper.
          // @see https://www.drupal.org/project/drupal/issues/994360
          $form[$policyTypeKey]['directives'][$directiveName]['options']['flags_wrapper'] = [
            '#type' => 'container',
            '#states' => [
              'visible' => [
                [':input[name="' . $policyTypeKey . '[directives][' . $directiveName . '][base]"]' => ['!value' => 'none']],
              ],
            ],
          ];
          $form[$policyTypeKey]['directives'][$directiveName]['options']['flags_wrapper']['flags'] = [
            '#type' => 'checkboxes',
            '#parents' => [$policyTypeKey, 'directives', $directiveName, 'flags'],
            '#options' => [
              'unsafe-inline' => "<code>'unsafe-inline'</code>",
              'unsafe-eval' => "<code>'unsafe-eval'</code>",
              'unsafe-hashes' => "<code>'unsafe-hashes'</code>",
              'unsafe-allow-redirects' => "<code>'unsafe-allow-redirects'</code>",
              'strict-dynamic' => "<code>'strict-dynamic'</code>",
              'report-sample' => "<code>'report-sample'</code>",
            ],
            '#default_value' => $config->get($policyTypeKey . '.directives.' . $directiveName . '.flags') ?: [],
          ];
        }
        if (!empty($autoDirectives[$directiveName])) {
          $form[$policyTypeKey]['directives'][$directiveName]['options']['auto'] = [
            '#type' => 'textarea',
            '#parents' => [$policyTypeKey, 'directives', $directiveName, 'auto'],
            '#title' => 'Auto Sources',
            '#value' => implode(' ', $autoDirectives[$directiveName]),
            '#disabled' => TRUE,
          ];
        }
        $form[$policyTypeKey]['directives'][$directiveName]['options']['sources'] = [
          '#type' => 'textarea',
          '#parents' => [$policyTypeKey, 'directives', $directiveName, 'sources'],
          '#title' => $this->t('Additional Sources'),
          '#description' => $this->t('Additional domains or protocols to allow for this directive.'),
          '#default_value' => implode(' ', $config->get($policyTypeKey . '.directives.' . $directiveName . '.sources') ?: []),
          '#states' => [
            'visible' => [
              [':input[name="' . $policyTypeKey . '[directives][' . $directiveName . '][base]"]' => ['!value' => 'none']],
            ],
          ],
        ];
      }

      $form[$policyTypeKey]['directives']['child-src']['options']['note'] = [
        '#type' => 'markup',
        '#markup' => '<em>' . $this->t('Instead of child-src, nested browsing contexts and workers should use the frame-src and worker-src directives, respectively.') . '</em>',
        '#weight' => -10,
      ];

      if ($policyTypeKey === 'enforce') {
        // block-all-mixed content is a no-op if upgrade-insecure-requests is
        // enabled.
        // @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/block-all-mixed-content
        $form[$policyTypeKey]['directives']['block-all-mixed-content']['#states'] = [
          'disabled' => [
            [':input[name="' . $policyTypeKey . '[directives][upgrade-insecure-requests][enable]"]' => ['checked' => TRUE]],
          ],
        ];
      }

      $form[$policyTypeKey]['directives']['plugin-types']['#states'] = [
        'visible' => [
          [':input[name="' . $policyTypeKey . '[directives][object-src][base]"]' => ['!value' => 'none']],
        ],
      ];

      $form[$policyTypeKey]['directives']['plugin-types']['options']['mime-types'] = [
        '#type' => 'textfield',
        '#parents' => [$policyTypeKey, 'directives', 'plugin-types', 'mime-types'],
        '#title' => $this->t('MIME Types'),
        '#default_value' => implode(' ', $config->get($policyTypeKey . '.directives.plugin-types') ?: []),
      ];

      // 'sandbox' token values are defined by HTML specification for the iframe
      // sandbox attribute.
      // @see https://www.w3.org/TR/CSP/#directive-sandbox
      // @see https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox
      $form[$policyTypeKey]['directives']['sandbox']['options']['keys'] = [
        '#type' => 'checkboxes',
        '#parents' => [$policyTypeKey, 'directives', 'sandbox', 'keys'],
        '#options' => [
          'allow-forms' => '<code>allow-forms</code>',
          'allow-modals' => '<code>allow-modals</code>',
          'allow-orientation-lock' => '<code>allow-orientation-lock</code>',
          'allow-pointer-lock' => '<code>allow-pointer-lock</code>',
          'allow-popups' => '<code>allow-popups</code>',
          'allow-popups-to-escape-sandbox' => '<code>allow-popups-to-escape-sandbox</code>',
          'allow-presentation' => '<code>allow-presentation</code>',
          'allow-same-origin' => '<code>allow-same-origin</code>',
          'allow-scripts' => '<code>allow-scripts</code>',
          'allow-top-navigation' => '<code>allow-top-navigation</code>',
          'allow-top-navigation-by-user-activation' => '<code>allow-top-navigation-by-user-activation</code>',
        ],
        '#default_value' => $config->get($policyTypeKey . '.directives.sandbox') ?: [],
      ];

      $form[$policyTypeKey]['directives']['require-sri-for']['options']['keys'] = [
        '#type' => 'checkboxes',
        '#parents' => [$policyTypeKey, 'directives', 'require-sri-for', 'keys'],
        '#options' => [
          'script' => '<code>script</code>',
          'style' => '<code>style</code>',
        ],
        '#default_value' => $config->get($policyTypeKey . '.directives.require-sri-for') ?: [],
      ];
    }

    // Skip this check when building the form before validation/submission.
    if (empty($form_state->getUserInput())) {
      $enabledPolicies = array_filter(array_keys($policyTypes), function ($policyTypeKey) use ($config) {
        return $config->get($policyTypeKey . '.enable');
      });
      if (empty($enabledPolicies)) {
        $this->messenger()
          ->addWarning($this->t('No policies are currently enabled.'));
      }
    }

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {

    $reportingHandlerPluginId = $form_state->getValue(['report', 'handler']);
    $form['report'][$reportingHandlerPluginId]['#CspReportingHandlerPlugin']
      ->validateForm($form['report'][$reportingHandlerPluginId], $form_state);

    foreach (['report-only', 'enforce'] as $policyTypeKey) {

      $directiveNames = $this->getConfigurableDirectives();
      foreach ($directiveNames as $directiveName) {
        if (($directiveSources = $form_state->getValue([$policyTypeKey, 'directives', $directiveName, 'sources']))) {
          $invalidSources = array_reduce(
            preg_split('/,?\s+/', $directiveSources),
            function ($return, $value) {
              return $return || !(preg_match('<^([a-z]+:)?$>', $value) || static::isValidHost($value));
            },
            FALSE
          );
          if ($invalidSources) {
            $form_state->setError(
              $form[$policyTypeKey]['directives'][$directiveName]['options']['sources'],
              $this->t('Invalid domain or protocol provided.')
            );
          }
        }
      }

      // Don't validate if not enabled; value will be skipped on save.
      if ($form_state->getValue([$policyTypeKey, 'directives', 'plugin-types', 'enable'])) {
        $invalidTypes = array_reduce(
          preg_split(
            '/,?\s+/',
            $form_state->getValue([$policyTypeKey, 'directives', 'plugin-types', 'mime-types'], '')
          ),
          function ($return, $value) {
            return $return || !preg_match('<^([\w-]+/[\w-]+)?$>', $value);
          },
          FALSE
        );
        if ($invalidTypes) {
          $form_state->setError(
            $form[$policyTypeKey]['directives']['plugin-types']['options']['mime-types'],
            $this->t('Invalid MIME-Type provided.')
          );
        }
      }
    }

    parent::validateForm($form, $form_state);
  }

  /**
   * Verifies the syntax of the given URL.
   *
   * Similar to UrlHelper::isValid(), except:
   * - protocol is optional; can only be http or https.
   * - domains must have at least a top-level and secondary domain.
   * - query is not allowed.
   *
   * @param string $url
   *   The URL to verify.
   *
   * @return bool
   *   TRUE if the URL is in a valid format, FALSE otherwise.
   */
  private static function isValidHost($url) {
    return (bool) preg_match("
        /^                                                      # Start at the beginning of the text
        (?:https?:\/\/)?                                        # Look for http or https schemes (optional)
        (?:
          (?:                                                   # A domain name or a IPv4 address
            (?:\*\.)?                                           # Wildcard prefix (optional)
            (?:(?:[a-z0-9\-\.]|%[0-9a-f]{2})+\.)+
            (?:[a-z0-9\-\.]|%[0-9a-f]{2})+
          )
          |(?:\[(?:[0-9a-f]{0,4}:)*(?:[0-9a-f]{0,4})\])         # or a well formed IPv6 address
        )
        (?::[0-9]+)?                                            # Server port number (optional)
        (?:[\/|\?]
          (?:[\w#!:\.\+=&@$'~*,;\/\(\)\[\]\-]|%[0-9a-f]{2})     # The path (optional)
        *)?
      $/xi", $url);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    // Script and Style must always be enabled.
    $autoDirectives = $this->libraryPolicyBuilder->getSources() + [
      'script-src' => [],
      'style-src' => [],
    ];

    $config = $this->config('csp.settings');

    $reportHandlerPluginId = $form_state->getValue(['report', 'handler']);
    $config->set('report', ['plugin' => $reportHandlerPluginId]);
    $reportHandlerOptions = $form_state->getValue(['report', $reportHandlerPluginId]);
    if ($reportHandlerOptions) {
      $config->set('report.options', $reportHandlerOptions);
    }

    $directiveNames = $this->getConfigurableDirectives();
    foreach (['report-only', 'enforce'] as $policyTypeKey) {
      $config->clear($policyTypeKey);

      $policyFormData = $form_state->getValue($policyTypeKey);

      $config->set($policyTypeKey . '.enable', !empty($policyFormData['enable']));
      if (empty($policyFormData['enable'])) {
        continue;
      }

      foreach ($directiveNames as $directiveName) {
        if (empty($policyFormData['directives'][$directiveName])) {
          continue;
        }

        $directiveFormData = $policyFormData['directives'][$directiveName];
        $directiveOptions = [];

        if (empty($directiveFormData['enable'])) {
          continue;
        }

        $directiveSchema = Csp::getDirectiveSchema($directiveName);

        if ($directiveSchema === Csp::DIRECTIVE_SCHEMA_BOOLEAN) {
          $directiveOptions = TRUE;
        }
        elseif (in_array($directiveSchema, [
          Csp::DIRECTIVE_SCHEMA_MEDIA_TYPE_LIST,
          Csp::DIRECTIVE_SCHEMA_TOKEN_LIST,
          Csp::DIRECTIVE_SCHEMA_OPTIONAL_TOKEN_LIST,
        ])) {
          if ($directiveName == 'plugin-types') {
            // If "object-src: none" all plugins will be blocked even if type is
            // allowed.  The form field is hidden and skips validation, so make
            // sure value is not saved.
            if (!empty($directiveFormData['mime-types']) && $policyFormData['directives']['object-src']['base'] != 'none') {
              $directiveOptions = preg_split('/,?\s+/', $directiveFormData['mime-types']);
            }
          }
          else {
            $directiveOptions = array_keys(array_filter($directiveFormData['keys']));
          }
        }
        elseif (in_array($directiveSchema, [
          Csp::DIRECTIVE_SCHEMA_SOURCE_LIST,
          Csp::DIRECTIVE_SCHEMA_ANCESTOR_SOURCE_LIST,
        ])) {
          if ($directiveFormData['base'] !== 'none') {
            if (!empty($directiveFormData['sources'])) {
              $directiveOptions['sources'] = array_filter(preg_split('/,?\s+/', $directiveFormData['sources']));
            }
            if ($directiveName != 'frame-ancestors') {
              $directiveFormData['flags'] = array_filter($directiveFormData['flags']);
              if (!empty($directiveFormData['flags'])) {
                $directiveOptions['flags'] = array_keys($directiveFormData['flags']);
              }
            }
          }

          // Don't store empty base type if no additional values set.
          // Always store non-empty base value.
          if (!($directiveFormData['base'] === '' && empty($directiveOptions) && empty($autoDirectives[$directiveName]))) {
            $directiveOptions['base'] = $directiveFormData['base'];
          }
        }

        if (!empty($directiveOptions) || $directiveSchema == Csp::DIRECTIVE_SCHEMA_OPTIONAL_TOKEN_LIST) {
          $config->set($policyTypeKey . '.directives.' . $directiveName, $directiveOptions);
        }
      }

    }

    $config->save();

    parent::submitForm($form, $form_state);
  }

}
