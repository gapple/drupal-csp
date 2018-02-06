<?php

namespace Drupal\csp\Form;

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
      '#description' => $this->t("Your report-uri.com subdomain."),
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
  public function submitForm(array &$form, FormStateInterface $form_state) {

    $this->config('csp.settings')
      ->set('enforce', $form_state->getValue('enforce'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
