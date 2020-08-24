<?php

namespace Drupal\csp_extras\Ajax;

use Drupal\Core\Ajax\CommandInterface;

/**
 * AJAX command for including additional assets.
 *
 * The 'add_assets' command instructs the client to load additional JS and CSS.
 *
 * This command is implemented by Drupal.AjaxCommands.prototype.add_assets()
 * defined in csp_extras/js/ajax.js.
 *
 * @ingroup ajax
 */
class AddAssetsCommand implements CommandInterface {

  /**
   * An array of assets keyed by their type (either 'script' or 'style').
   *
   * @var array[]
   */
  protected $assets;

  /**
   * Constructs a AddAssetsCommand object.
   *
   * @param array[] $assets
   *   An array of asset element definitions.
   */
  public function __construct(array $assets) {
    $this->assets = array_values($assets);
  }

  /**
   * Implements Drupal\Core\Ajax\CommandInterface:render().
   */
  public function render() {
    return [
      'command' => 'add_assets',
      'assets' => $this->assets,
    ];
  }

}
