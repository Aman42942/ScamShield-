# ScamShield Page Structure

All pages inherit from `frontend/templates/base.html`, so navigation, sidebar, top bar, theme switcher and responsive shell stay consistent.

## Page flow

Home/Dashboard → choose input → Analyze Threat → Result → History / Analytics

Supporting pages:
- Safety Guide: prevention and safe-response guidance
- About: project purpose, ML pipeline and architecture

## Template hierarchy

base.html
├── index.html
├── result.html
├── history.html
├── analytics.html
├── guide.html
└── about.html

## Frontend JavaScript

- `app.js`: shared interactions, theme, sidebar, scanner tabs, upload and demo examples.
- `pages.js`: history filtering and analytics rendering.
