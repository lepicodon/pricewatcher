(() => {
  try {
    const colorScheme = localStorage.getItem("color-scheme");
    if (colorScheme === "light" || colorScheme === "dark") {
      const meta = document.querySelector('meta[name="color-scheme"]');
      if (meta) {
        meta.content = colorScheme;
      }
      document.documentElement.classList.remove("theme-light", "theme-dark");
      document.documentElement.classList.add(`theme-${colorScheme}`);
    }
  } catch {
    // Ignore storage access errors in restricted contexts.
  }
})();
