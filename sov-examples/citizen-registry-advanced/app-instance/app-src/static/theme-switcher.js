(() => {
    const storageKey = 'citizen-registry-theme';
    const root = document.documentElement;
    let savedTheme = null;

    try {
        savedTheme = window.localStorage.getItem(storageKey);
    } catch {
        savedTheme = null;
    }

    const preferredTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    const initialTheme = savedTheme === 'dark' || savedTheme === 'light' ? savedTheme : preferredTheme;
    root.dataset.theme = initialTheme;

    window.setCitizenRegistryTheme = theme => {
        const nextTheme = theme === 'dark' ? 'dark' : 'light';
        root.dataset.theme = nextTheme;
        try {
            window.localStorage.setItem(storageKey, nextTheme);
        } catch {
            // Theme remains active for the current page when storage is unavailable.
        }
        document.querySelectorAll('[data-theme-toggle]').forEach(button => {
            button.textContent = nextTheme === 'dark' ? 'Light mode' : 'Dark mode';
            button.setAttribute('aria-pressed', String(nextTheme === 'dark'));
        });
    };

    window.toggleCitizenRegistryTheme = () => {
        window.setCitizenRegistryTheme(root.dataset.theme === 'dark' ? 'light' : 'dark');
    };

    document.addEventListener('DOMContentLoaded', () => window.setCitizenRegistryTheme(root.dataset.theme));
})();
