<?php

namespace Drupal\csp\Form;

use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\csp\Csp;
use Drupal\csp\LibraryPolicyBuilder;
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
   */
  public function __construct(ConfigFactoryInterface $config_factory, LibraryPolicyBuilder $libraryPolicyBuilder) {
    parent::__construct($config_factory);
    $this->libraryPolicyBuilder = $libraryPolicyBuilder;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('config.factory'),
      $container->get('csp.library_policy_builder')
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
   * Get the directives which don't use a source-list.
   *
   * @return array
   *   An array of directive names.
   */
  private function getCustomOptionsDirectives() {
    return [
      'plugin-types',
      'sandbox',
      'block-all-mixed-content',
      'require-sri-for',
      'upgrade-insecure-requests',
    ];
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
      '#options' => [
        'csp-module' => $this->t('Internal'),
        'report-uri-com' => 'Report-URI.com',
        'uri' => $this->t('External URI'),
        '' => $this->t('None'),
      ],
      '#default_value' => $config->get('report.handler'),
    ];
    $form['report']['none'] = [
      '#type' => 'item',
      '#description' => $this->t('Reporting is disabled.'),
      '#states' => [
        'visible' => [
          ':input[name="report[handler]"]' => ['value' => ''],
        ],
      ],
    ];
    $form['report']['csp-module'] = [
      '#type' => 'item',
      '#description' => $this->t('Reports will be added to the site log.'),
      '#states' => [
        'visible' => [
          ':input[name="report[handler]"]' => ['value' => 'csp-module'],
        ],
      ],
    ];
    $form['report']['report-uri-com']['subdomain'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Subdomain'),
      '#description' => $this->t('Your <a href=":url">Report-URI.com subdomain</a>.', [
        ':url' => 'https://report-uri.com/account/setup/',
      ]),
      '#default_value' => $config->get('report.options.subdomain'),
      '#states' => [
        'visible' => [
          ':input[name="report[handler]"]' => ['value' => 'report-uri-com'],
        ],
        'required' => [
          ':input[name="report[handler]"]' => ['value' => 'report-uri-com'],
        ],
      ],
    ];
    $form['report']['uri']['uri'] = [
      '#type' => 'textfield',
      '#title' => $this->t('URI'),
      '#description' => $this->t('The URI to send reports to.'),
      '#default_value' => $config->get('report.options.uri'),
      '#states' => [
        'visible' => [
          ':input[name="report[handler]"]' => ['value' => 'uri'],
        ],
        'required' => [
          ':input[name="report[handler]"]' => ['value' => 'uri'],
        ],
      ],
    ];

    $form['policies'] = [
      '#type' => 'vertical_tabs',
      '#title' => $this->t('Policies'),
    ];

    $directiveNames = $this->getConfigurableDirectives();
    // These directives may have custom options instead of sources.
    $customOptionDirectives = $this->getCustomOptionsDirectives();
    $enforceOnlyDirectives = [
      // upgrade-insecure-requests is ignored when sent via a
      // Content-Security-Policy-Report-Only header.
      // @see https://w3c.github.io/webappsec-upgrade-insecure-requests/#delivery
      'upgrade-insecure-requests',
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

        $form[$policyTypeKey]['directives'][$directiveName] = [
          '#type' => 'container',
        ];

        $forceEnable = isset($autoDirectives[$directiveName]);

        $form[$policyTypeKey]['directives'][$directiveName]['enable'] = [
          '#type' => 'checkbox',
          '#title' => $directiveName,
          '#default_value' => $forceEnable || !empty($config->get($policyTypeKey . '.directives.' . $directiveName)),
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

        if (in_array($directiveName, $customOptionDirectives)) {
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

        // Some directives do not support unsafe flags.
        // @see https://www.w3.org/TR/CSP/#grammardef-ancestor-source-list
        if (!in_array($directiveName, ['frame-ancestors'])) {
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
            ],
            '#default_value' => $config->get($policyTypeKey . '.directives.' . $directiveName . '.flags') ?: [],
          ];
        }
        if (!empty($autoDirectives[$directiveName])) {
          $form[$policyTypeKey]['directives'][$directiveName]['options']['auto'] = [
            '#type' => 'textfield',
            '#parents' => [$policyTypeKey, 'directives', $directiveName, 'auto'],
            '#title' => 'Auto Sources',
            '#value' => implode(' ', $autoDirectives[$directiveName]),
            '#disabled' => TRUE,
          ];
        }
        $form[$policyTypeKey]['directives'][$directiveName]['options']['sources'] = [
          '#type' => 'textfield',
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
        drupal_set_message($this->t('No policies are currently enabled.'), 'warning');
      }
    }

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {

    $reportHandler = $form_state->getValue(['report', 'handler']);
    if ($reportHandler == 'report-uri-com') {
      if (!preg_match('/^[a-z\d]{4,30}$/i', $form_state->getValue(['report', 'report-uri-com', 'subdomain']))) {
        $form_state->setError($form['report']['report-uri-com']['subdomain'], 'Must be 4-30 alphanumeric characters.');
      }
    }
    elseif ($reportHandler == 'uri') {
      $uri = $form_state->getValue(['report', 'uri', 'uri']);
      if (!(UrlHelper::isValid($uri, TRUE) && preg_match('/^https?:/', $uri))) {
        $form_state->setError($form['report']['uri']['uri'], 'Must be a valid http or https URL.');
      }
    }

    foreach (['report-only', 'enforce'] as $policyTypeKey) {

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
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {

    $config = $this->config('csp.settings')
      ->set('enforce', $form_state->getValue('enforce'));

    $reportHandler = $form_state->getValue(['report', 'handler']);
    $config->set('report.handler', $reportHandler);
    if ($reportHandler == 'report-uri-com') {
      $config->set(
        'report.options',
        [
          'subdomain' => $form_state->getValue(['report', 'report-uri-com', 'subdomain']),
        ]
      );
    }
    elseif ($reportHandler == 'uri') {
      $config->set(
        'report.options',
        [
          'uri' => $form_state->getValue(['report', 'uri', 'uri']),
        ]
      );
    }
    else {
      $config->clear('report.options');
    }

    $directiveNames = $this->getConfigurableDirectives();
    $booleanDirectives = ['block-all-mixed-content', 'upgrade-insecure-requests'];
    $arrayDirectives = ['plugin-types', 'sandbox', 'require-sri-for'];
    $customOptionsDirectives = $this->getCustomOptionsDirectives();
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

        if (in_array($directiveName, $booleanDirectives)) {
          $directiveOptions = TRUE;
        }
        elseif (in_array($directiveName, $arrayDirectives)) {
          if ($directiveName == 'plugin-types') {
            if (!empty($directiveFormData['mime-types'])) {
              $directiveOptions = preg_split('/,?\s+/', $directiveFormData['mime-types']);
            }
          }
          else {
            $directiveOptions = array_keys(array_filter($directiveFormData['keys']));
          }
        }
        elseif (!in_array($directiveName, $customOptionsDirectives)) {
          $directiveOptions['base'] = $directiveFormData['base'];
          if ($directiveOptions['base'] !== 'none') {
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
        }

        if (!empty($directiveOptions)) {
          $config->set($policyTypeKey . '.directives.' . $directiveName, $directiveOptions);
        }
      }

    }

    $config->save();

    parent::submitForm($form, $form_state);
  }

}
