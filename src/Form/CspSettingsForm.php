<?php

namespace Drupal\csp\Form;

use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\csp\Csp;

/**
 * Form for editing Content Security Policy module settings.
 */
class CspSettingsForm extends ConfigFormBase {

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
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('csp.settings');

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

    // Exclude some directives
    // - Reporting directives have dedicated fields elsewhere in the form.
    // - 'referrer' is deprecated in favour of the Referrer-Policy header, and
    //   not supported in most browsers.
    $directives = array_diff(
      Csp::getDirectiveNames(),
      ['report-uri', 'report-to', 'referrer']
    );
    // These directives may have custom options instead of sources.
    $customOptionDirectives = [
      'plugin-types',
      'sandbox',
      'block-all-mixed-content',
      'require-sri-for',
      'upgrade-insecure-requests',
    ];
    // Directives which do not support unsafe flags.
    $noUnsafe = [
      'frame-ancestors',
    ];

    $policyTypes = [
      'report-only' => $this->t('Report Only'),
      'enforced' => $this->t('Enforced'),
    ];
    foreach ($policyTypes as $policyTypeKey => $policyTypeName) {
      $form[$policyTypeKey] = [
        '#type' => 'details',
        '#title' => $policyTypeName,
        '#group' => 'policies',
        '#tree' => TRUE,
      ];

      $form[$policyTypeKey]['enable'] = [
        '#type' => 'checkbox',
        '#title' => $this->t("Enable '@type'", ['@type' => $policyTypeName]),
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

      foreach ($directives as $directive) {
        $form[$policyTypeKey]['directives'][$directive] = [
          '#type' => 'container',
        ];
        $form[$policyTypeKey]['directives'][$directive]['enable'] = [
          '#type' => 'checkbox',
          '#title' => $directive,
        ];
        $form[$policyTypeKey]['directives'][$directive]['options'] = [
          '#type' => 'container',
          '#states' => [
            'visible' => [
              ':input[name="' . $policyTypeKey . '[directives][' . $directive . '][enable]"]' => ['checked' => TRUE],
            ],
          ],
        ];

        if (in_array($directive, $customOptionDirectives)) {
          continue;
        }

        $form[$policyTypeKey]['directives'][$directive]['options']['base'] = [
          '#type' => 'radios',
          '#parents' => [$policyTypeKey, 'directives', $directive, 'base'],
          '#options' => [
            'self' => "Self",
            'none' => "None",
            'any' => "Any",
            '' => '<em>n/a</em>',
          ],
          '#default_value' => 'self',
        ];

        if (!in_array($directive, $noUnsafe)) {
          // States currently don't work on checkboxes elements, so need to be
          // applied to a wrapper.
          // @see https://www.drupal.org/project/drupal/issues/994360
          $form[$policyTypeKey]['directives'][$directive]['options']['flags_wrapper'] = [
            '#type' => 'container',
            '#states' => [
              'visible' => [
                [':input[name="' . $policyTypeKey . '[directives][' . $directive . '][base]"]' => ['!value' => 'none']],
              ],
            ],
          ];
          $form[$policyTypeKey]['directives'][$directive]['options']['flags_wrapper']['flags'] = [
            '#type' => 'checkboxes',
            '#parents' => [$policyTypeKey, 'directives', $directive, 'flags'],
            '#options' => [
              'unsafe-inline' => "<code>'unsafe-inline'</code>",
              'unsafe-eval' => "<code>'unsafe-eval'</code>",
            ],
            '#default_value' => [],
          ];
        }
        $form[$policyTypeKey]['directives'][$directive]['options']['sources'] = [
          '#type' => 'textfield',
          '#title' => $this->t('Additional Sources'),
          '#description' => $this->t('Additional domains or protocols to allow for this directive.'),
          '#parents' => [$policyTypeKey, 'directives', $directive, 'sources'],
          '#states' => [
            'visible' => [
              [':input[name="' . $policyTypeKey . '[directives][' . $directive . '][base]"]' => ['!value' => 'none']],
            ],
          ],
        ];
      }

      $form[$policyTypeKey]['directives']['plugin-types']['options']['mime-types'] = [
        '#type' => 'textfield',
        '#parents' => [$policyTypeKey, 'directives', 'plugin-types', 'mime-types'],
        '#title' => $this->t('MIME Types'),
      ];

      $form[$policyTypeKey]['directives']['sandbox']['options']['values'] = [
        '#type' => 'checkboxes',
        '#parents' => [$policyTypeKey, 'directives', 'sandbox', 'values'],
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
      ];

      $form[$policyTypeKey]['directives']['require-sri-for']['options']['directives'] = [
        '#type' => 'checkboxes',
        '#parents' => [$policyTypeKey, 'directives', 'require-sri-for', 'directives'],
        '#options' => [
          'script' => '<code>script</code>',
          'style' => '<code>style</code>',
        ],
      ];
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

    $config->save();

    parent::submitForm($form, $form_state);
  }

}
