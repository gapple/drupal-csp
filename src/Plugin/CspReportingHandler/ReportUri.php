<?php

namespace Drupal\csp\Plugin\CspReportingHandler;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\csp\Csp;
use Drupal\csp\Plugin\ReportingHandlerBase;

/**
 * CSP Reporting Plugin for ReportURI service.
 *
 * @CspReportingHandler(
 *   id = "report-uri-com",
 *   label = "Report URI",
 *   description = @Translation("Reports will be sent to a ReportURI.com account."),
 * )
 *
 * @see report-uri.com
 */
class ReportUri extends ReportingHandlerBase {

  use StringTranslationTrait;

  /**
   * {@inheritdoc}
   */
  public function getForm(array $form) {

    $form['subdomain'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Subdomain'),
      '#description' => $this->t('Your <a href=":url">Report-URI.com subdomain</a>.', [
        ':url' => 'https://report-uri.com/account/setup/',
      ]),
      '#default_value' => isset($this->configuration['subdomain']) ? $this->configuration['subdomain'] : '',
      '#states' => [
        'required' => [
          ':input[name="' . $this->configuration['type'] . '[enable]"]' => ['checked' => TRUE],
          ':input[name="' . $this->configuration['type'] . '[reporting][handler]"]' => ['value' => $this->pluginId],
        ],
      ],
    ];

    unset($form['#description']);

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    $subdomain = $form_state->getValue($form['subdomain']['#parents']);;
    if (!preg_match('/^[a-z\d]{4,30}$/i', $subdomain)) {
      $form_state->setError($form['subdomain'], 'Must be 4-30 alphanumeric characters.');
    }
  }

  /**
   * {@inheritdoc}
   */
  public function alterPolicy(Csp $policy) {
    $reportUri = 'https://' . $this->configuration['subdomain'] . '.report-uri.com/r/d/csp/' . (($this->configuration['type'] == 'enforce') ? 'enforce' : 'reportOnly');
    $policy->setDirective('report-uri', $reportUri);
  }

}