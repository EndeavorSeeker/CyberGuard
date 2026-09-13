# i18n overhaul checklist (in progress)

- [ ] Audit & update: phone-security.html
- [ ] Audit & update: browser-security.html
- [ ] Audit & update: pc-security.html
- [ ] Audit & update: password-security.html
- [ ] Audit & update: phishing-prevention.html
- [ ] Audit & update: data-protection.html

- [ ] Refactor all inline scripts to use cgTranslate('key') for every injected visible string (no hardcoded English)
- [ ] Verify no remaining visible static strings without data-i18n in the 6 templates
- [ ] Produce JSON map of newly added i18n keys -> original English

