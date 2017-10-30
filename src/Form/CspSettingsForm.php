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
