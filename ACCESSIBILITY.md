# Accessibility

Watchtower targets [WCAG 2.2 Level AA](https://www.w3.org/TR/WCAG22/) for its web application. This target includes and extends the WCAG 2.1 Level AA technical standard incorporated into the [U.S. Department of Justice's ADA Title II web and mobile application rule](https://www.ada.gov/resources/2024-03-08-web-rule/) for state and local governments.

Accessibility is a release requirement, not a separate interface. The same application must support keyboard navigation, screen readers, browser zoom and reflow, high-contrast modes, reduced motion, light and dark themes, and touch input.

## Current engineering baseline

- Semantic landmarks, headings, labels, table captions, and scoped column headers.
- A keyboard-visible skip link and consistent high-contrast focus indicators.
- Text alternatives or accessible names for non-text controls.
- Programmatic current, pressed, expanded, busy, error, and status states.
- Minimum 44-pixel primary control targets and 24-pixel-or-larger secondary targets.
- Light and dark palettes designed for WCAG AA text and non-text contrast.
- Reflow without page-level horizontal scrolling at 320 CSS pixels; data tables may scroll within their own labeled region when their two-dimensional relationships require it.
- Support for `prefers-reduced-motion` and Windows forced-colors mode.
- Automated axe checks for both the connection screen and authenticated dashboard in CI.

## Verification policy

Every material UI change should pass the TypeScript build, automated axe regression tests, keyboard-only browser testing, 200% and 400% zoom/reflow checks, light/dark contrast review, and a screen-reader smoke test before release.

Automated tools detect only a subset of accessibility barriers. Passing CI does not by itself establish WCAG conformance, ADA compliance, or legal certification. Production releases also require human testing with representative assistive technologies and workflows, including at least NVDA with Chrome or Firefox, JAWS with Chrome, and VoiceOver with Safari.

## Reporting a barrier

Please open a GitHub issue describing the page, action, expected result, assistive technology or input method, browser, operating system, and observed barrier. Do not include CJI, credentials, customer evidence, or other sensitive information in a public issue.
