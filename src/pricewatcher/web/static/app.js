/**
 * PriceWatcher Web UI ES module entrypoint.
 * Executed deferred once the HTML document is parsed.
 */

import { initManagePage } from "./manage.js";
import { initSettingsPage } from "./settings.js";
import { initThemeAndUi } from "./ui.js";
import { initWatchDetailPage } from "./watch_detail.js";

initThemeAndUi();
initManagePage();
initSettingsPage();
initWatchDetailPage();
