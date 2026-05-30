const THEME_STORAGE_KEY = 'preferred-theme';
const DARK_THEME = 'dark';
const LIGHT_THEME = 'light';
const SCROLL_TOP_VISIBILITY_THRESHOLD = 420;

const themeToggle = document.querySelector('#switch_dark_light_theme');
const navToggle = document.querySelector('#nav-toggle');
const navLinks = document.querySelectorAll('nav ul a');
const scrollToTopButton = document.querySelector('.scroll-to-top');
const prefersDarkTheme = window.matchMedia('(prefers-color-scheme: dark)');

function persistTheme(theme) {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch (error) {
    // Cookies keep the preference working in browsers where storage is blocked.
    document.cookie = `theme=${theme}; expires=Fri, 31 Dec 9999 23:59:59 GMT; path=/; SameSite=Lax`;
  }
}

function readPersistedTheme() {
  try {
    const storedTheme = localStorage.getItem(THEME_STORAGE_KEY);

    if (storedTheme === DARK_THEME || storedTheme === LIGHT_THEME) {
      return storedTheme;
    }
  } catch (error) {
    // Fall back to the legacy cookie used by previous versions of the site.
  }

  const cookieTheme = decodeURIComponent(document.cookie)
    .split(';')
    .map((value) => value.trim())
    .find((value) => value.startsWith('theme='));

  return cookieTheme ? cookieTheme.split('=')[1] : null;
}

function applyTheme(theme, shouldPersist = true) {
  const normalizedTheme = theme === DARK_THEME ? DARK_THEME : LIGHT_THEME;

  document.documentElement.setAttribute('data-theme', normalizedTheme);

  if (themeToggle) {
    themeToggle.checked = normalizedTheme === DARK_THEME;
  }

  if (shouldPersist) {
    persistTheme(normalizedTheme);
  }
}

function getInitialTheme() {
  return readPersistedTheme() || (prefersDarkTheme.matches ? DARK_THEME : LIGHT_THEME);
}

function setMenuState(isOpen) {
  if (!navToggle) {
    return;
  }

  navToggle.checked = isOpen;
  document.body.classList.toggle('menu-open', isOpen);
}

function scroll_manager(input) {
  setMenuState(input.checked);
}

function filterElements(input, target) {
  const query = input.value.trim().toLowerCase();
  const targets = document.querySelectorAll(target);

  targets.forEach((element) => {
    const isVisible = query.length === 0 || element.textContent.toLowerCase().includes(query);
    element.classList.toggle('is-filtered-out', !isVisible);
  });
}


function updateScrollToTopButton() {
  if (!scrollToTopButton) {
    return;
  }

  const shouldShowButton = window.scrollY > SCROLL_TOP_VISIBILITY_THRESHOLD;
  scrollToTopButton.classList.toggle('is-visible', shouldShowButton);
}

applyTheme(getInitialTheme(), false);
updateScrollToTopButton();

themeToggle?.addEventListener('change', (event) => {
  applyTheme(event.currentTarget.checked ? DARK_THEME : LIGHT_THEME);
});

prefersDarkTheme.addEventListener?.('change', (event) => {
  if (!readPersistedTheme()) {
    applyTheme(event.matches ? DARK_THEME : LIGHT_THEME, false);
  }
});

navToggle?.addEventListener('change', (event) => {
  setMenuState(event.currentTarget.checked);
});

navLinks.forEach((link) => {
  link.addEventListener('click', () => setMenuState(false));
});

scrollToTopButton?.addEventListener('click', () => {
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

window.addEventListener('scroll', updateScrollToTopButton, { passive: true });

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    setMenuState(false);
  }
});
