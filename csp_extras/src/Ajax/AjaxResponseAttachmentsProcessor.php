<?php

namespace Drupal\csp_extras\Ajax;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Ajax\AjaxResponse;
use Drupal\Core\Ajax\SettingsCommand;
use Drupal\Core\Asset\AssetResolverInterface;
use Drupal\Core\Asset\AttachedAssets;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Render\AttachmentsInterface;
use Drupal\Core\Render\AttachmentsResponseProcessorInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Processes attachments of AJAX responses.
 *
 * @see \Drupal\Core\Ajax\AjaxResponse
 * @see \Drupal\Core\Render\MainContent\AjaxRenderer
 */
class AjaxResponseAttachmentsProcessor implements AttachmentsResponseProcessorInterface {

  /**
   * The asset resolver service.
   *
   * @var \Drupal\Core\Asset\AssetResolverInterface
   */
  protected $assetResolver;

  /**
   * A config object for the system performance configuration.
   *
   * @var \Drupal\Core\Config\Config
   */
  protected $config;

  /**
   * The request stack.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  protected $requestStack;

  /**
   * The module handler.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  protected $moduleHandler;

  /**
   * The time service.
   *
   * @var \Drupal\Component\Datetime\TimeInterface
   */
  protected $time;

  /**
   * Constructs a AjaxResponseAttachmentsProcessor object.
   *
   * @param \Drupal\Core\Asset\AssetResolverInterface $asset_resolver
   *   An asset resolver.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   A config factory for retrieving required config objects.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request_stack
   *   The request stack.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $module_handler
   *   The module handler.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   */
  public function __construct(
    AssetResolverInterface $asset_resolver,
    ConfigFactoryInterface $config_factory,
    RequestStack $request_stack,
    ModuleHandlerInterface $module_handler,
    TimeInterface $time
  ) {
    $this->assetResolver = $asset_resolver;
    $this->config = $config_factory->get('system.performance');
    $this->requestStack = $request_stack;
    $this->moduleHandler = $module_handler;
    $this->time = $time;
  }

  /**
   * {@inheritdoc}
   */
  public function processAttachments(AttachmentsInterface $response) {
    // @todo Convert to assertion once https://www.drupal.org/node/2408013 lands
    if (!$response instanceof AjaxResponse) {
      throw new \InvalidArgumentException('\Drupal\Core\Ajax\AjaxResponse instance expected.');
    }

    $request = $this->requestStack->getCurrentRequest();

    if ($response->getContent() == '{}') {
      $response->setData($this->buildAttachmentsCommands($response, $request));
    }

    return $response;
  }

  /**
   * Prepares the AJAX commands to attach assets.
   *
   * @param \Drupal\Core\Ajax\AjaxResponse $response
   *   The AJAX response to update.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request object that the AJAX is responding to.
   *
   * @return array
   *   An array of commands ready to be returned as JSON.
   */
  protected function buildAttachmentsCommands(AjaxResponse $response, Request $request) {
    $ajax_page_state = $request->request->get('ajax_page_state');

    // Aggregate CSS/JS if necessary, but only during normal site operation.
    $optimize_css = !defined('MAINTENANCE_MODE') && $this->config->get('css.preprocess');
    $optimize_js = !defined('MAINTENANCE_MODE') && $this->config->get('js.preprocess');

    $attachments = $response->getAttachments();

    // Resolve the attached libraries into asset collections.
    $assets = new AttachedAssets();
    $assets->setLibraries(isset($attachments['library']) ? $attachments['library'] : [])
      ->setAlreadyLoadedLibraries(isset($ajax_page_state['libraries']) ? explode(',', $ajax_page_state['libraries']) : [])
      ->setSettings(isset($attachments['drupalSettings']) ? $attachments['drupalSettings'] : []);
    $css_assets = $this->assetResolver->getCssAssets($assets, $optimize_css);
    list($js_assets_header, $js_assets_footer) = $this->assetResolver->getJsAssets($assets, $optimize_js);

    // First, AttachedAssets::setLibraries() ensures duplicate libraries are
    // removed: it converts it to a set of libraries if necessary. Second,
    // AssetResolver::getJsSettings() ensures $assets contains the final set of
    // JavaScript settings. AttachmentsResponseProcessorInterface also mandates
    // that the response it processes contains the final attachment values, so
    // update both the 'library' and 'drupalSettings' attachments accordingly.
    $attachments['library'] = $assets->getLibraries();
    $attachments['drupalSettings'] = $assets->getSettings();
    $response->setAttachments($attachments);

    // Render the HTML to load these files, and add AJAX commands to insert this
    // HTML in the page. Settings are handled separately, afterwards.
    $settings = [];
    if (isset($js_assets_header['drupalSettings'])) {
      $settings = $js_assets_header['drupalSettings']['data'];
      unset($js_assets_header['drupalSettings']);
    }
    if (isset($js_assets_footer['drupalSettings'])) {
      $settings = $js_assets_footer['drupalSettings']['data'];
      unset($js_assets_footer['drupalSettings']);
    }

    // Remove assets that are not available to all browsers.
    $css_assets = array_filter($css_assets, [$this, 'filterBrowserAssets']);
    $js_assets = array_filter(array_merge($js_assets_header, $js_assets_footer), [$this, 'filterBrowserAssets']);

    if (!empty($css_assets) || !empty($js_assets)) {
      $default_query_string = \Drupal::state()->get('system.css_js_query_string') ?: '0';

      $css_assets = array_map(
        function ($css_asset) use ($default_query_string) {
          $asset = [
            'type' => 'stylesheet',
            'attributes' => [
              'media' => $css_asset['media'],
              'href' => file_url_transform_relative(file_create_url($css_asset['data'])),
            ],
          ];

          if (isset($css_asset['attributes'])) {
            $asset['attributes'] += $css_asset['attributes'];
          }

          // Only add the cache-busting query string if this isn't an
          // aggregate file.
          if ($css_asset['type'] == 'file' && !isset($css_asset['preprocessed'])) {
            $query_string_separator = (strpos($css_asset['data'], '?') !== FALSE) ? '&' : '?';
            $asset['attributes']['href'] .= $query_string_separator . $default_query_string;
          }
          return $asset;
        },
        $css_assets
      );

      $js_assets = array_map(
        function ($js_asset) use ($default_query_string) {
          $asset = [
            'type' => 'script',
            'attributes' => [
              'src' => file_url_transform_relative(file_create_url($js_asset['data'])),
            ],
          ];

          if (isset($js_asset['attributes'])) {
            $asset['attributes'] += $js_asset['attributes'];
          }

          // Only add the cache-busting query string if this isn't an
          // aggregate file.
          if ($js_asset['type'] == 'file' && !isset($js_asset['preprocessed'])) {
            $query_string = $js_asset['version'] == -1 ? $default_query_string : 'v=' . $js_asset['version'];
            $query_string_separator = (strpos($js_asset['data'], '?') !== FALSE) ? '&' : '?';
            $asset['attributes']['src'] .= $query_string_separator . ($js_asset['cache'] ? $query_string : $this->time->getRequestTime());
          }
          return $asset;
        },
        $js_assets
      );

      $response->addCommand(new AddAssetsCommand(array_merge($css_assets, $js_assets)), TRUE);
    }

    // Prepend a command to merge changes and additions to drupalSettings.
    if (!empty($settings)) {
      // During Ajax requests basic path-specific settings are excluded from
      // new drupalSettings values. The original page where this request comes
      // from already has the right values. An Ajax request would update them
      // with values for the Ajax request and incorrectly override the page's
      // values.
      // @see system_js_settings_alter()
      unset($settings['path']);
      $response->addCommand(new SettingsCommand($settings, TRUE), TRUE);
    }

    $commands = $response->getCommands();
    $this->moduleHandler->alter('ajax_render', $commands);

    return $commands;
  }

  /**
   * Filter function for assets that are browser-restricted.
   *
   * @param array $asset
   *   An asset definition.
   *
   * @return bool
   *   FALSE if the asset is restricted to certain browsers.
   */
  private static function filterBrowserAssets(array $asset) {
    // @see Drupal\Core\Render\Element\HtmlTag::preRenderConditionalComments
    if (
      (isset($asset['browsers']['IE']) && $asset['browsers']['IE'] !== TRUE)
      ||
      (isset($asset['browsers']['!IE']) && $asset['browsers']['!IE'] !== TRUE)
    ) {
      trigger_error('Library asset with browser restrictions was omitted from AJAX response.', E_USER_WARNING);
      return FALSE;
    }
    return TRUE;
  }

}
