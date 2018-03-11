/**
 * @file
 * Defines Javascript behaviors for the csp module admin form.
 */

(function ($, Drupal) {

  /**
   * Sets summary of policy tabs.
   *
   * @type {Drupal~behavior}
   *
   * @prop {Drupal~behaviorAttach} attach
   *   Attaches summary behaviour for policy form tabs.
   */
  Drupal.behaviors.cspPolicySummary = {
    attach(context) {
      $(context)
        .find('[data-drupal-selector="edit-policies"] > details')
        .each(function () {
          const $details = $(this);
          const elementPrefix = $details.data('drupal-selector');
          const createPolicyElementSelector = function (name) {
            return '[data-drupal-selector="' + elementPrefix + '-' + name + '"]';
          };

          $details.drupalSetSummary(function () {
            if ($details.find(createPolicyElementSelector('enable')).prop('checked')) {
              const directiveCount = $details
                .find(createPolicyElementSelector('directives') + ' [name$="[enable]"]:checked')
                .length;
              return Drupal.formatPlural(
                directiveCount,
                'Enabled, @directiveCount directive',
                'Enabled, @directiveCount directives',
                { '@directiveCount': directiveCount },
              );
            }

            return Drupal.t('Disabled');
          });
        });
    },
  };
}(jQuery, Drupal));
