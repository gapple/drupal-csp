<?php

namespace Drupal\csp\Form;

use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

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

    $form['enforce'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enforce'),
      '#description' => $this->t('Enable policy enforcement.  If disabled, policy is set to report-only.'),
      '#default_value' => $config->get('enforce'),
    ];

    $form['report'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Reporting'),
      '#tree' => TRUE,
    ];
    $form['report']['handler'] = [
      '#type' => 'select',
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
      ],
    ];

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
