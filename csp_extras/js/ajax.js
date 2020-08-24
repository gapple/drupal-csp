/**
 * @file
 * Provides add_assets command for Ajax responses.
 */

(function (window, Drupal) {

  /**
   * Command to add script and style assets.
   *
   * @param {Drupal.Ajax} [ajax]
   *   {@link Drupal.Ajax} object created by {@link Drupal.ajax}.
   * @param {object} response
   *   The response from the Ajax request.
   * @param {string} response.assets
   *   An object that contains the script and styles to be added.
   * @param {number} [status]
   *   The XMLHttpRequest status.
   */
  Drupal.AjaxCommands.prototype.add_assets = function (ajax, response, status) {
    response.assets.forEach(function (item) {
      var elem;
      var target = document.body;

      if (item.type === "script") {
        elem = document.createElement("script");
        if (typeof item.attributes.async === "undefined") {
          elem.async = false;
        }
      } else if (item.type === "stylesheet") {
        elem = document.createElement("link");
        elem.rel = "stylesheet";
        target = document.head;
      }

      Object.keys(item.attributes).forEach(function (key) {
        elem[key] = item.attributes[key];
      });

      target.appendChild(elem);
    });
  };

})(window, Drupal);
