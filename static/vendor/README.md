# vendor/

Third-party browser libraries live here as plain files, downloaded once and
served by this app.

Nothing in this project is compiled, bundled, or transpiled, and nothing is
fetched from a CDN at runtime. Two reasons that is worth the small hassle of
downloading a file:

- **The page keeps working.** A CDN outage, a DNS block, or a corporate proxy
  cannot take a self-hosted file away, and the version cannot change under you
  because someone re-tagged a release.
- **The Content-Security-Policy stays tight.** `server/middleware` sets
  `script-src 'self'`, so a `<script src="https://cdn...">` is refused by the
  browser. That is the policy working, not a bug -- vendor the file instead of
  loosening it.

Add one with the helper, which downloads the file and prints the tag to paste:

```bash
misc/vendor.sh https://cdnjs.cloudflare.com/ajax/libs/htmx.org/2.0.4/htmx.min.js
```

Then reference it from your HTML:

```html
<script src="/vendor/htmx.min.js"></script>
```

Commit what lands here. It is part of the app, not a build artifact.

## What is here

| File | From |
|---|---|
| `bootstrap.min.css`, `bootstrap.bundle.min.js` | Bootstrap 5.3.8 (the bundle includes Popper) |
| `bootstrap-icons.min.css`, `fonts/bootstrap-icons.woff2`, `fonts/bootstrap-icons.woff` | Bootstrap Icons 1.13.1 |
| `qrcode.js` | qrcode-generator 1.4.4 (MIT), for the two-factor setup screen |

The icon stylesheet loads its font from `fonts/` next to it, so keep that
layout. To upgrade, delete these files and fetch the new version:

```bash
misc/vendor.sh https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.8/css/bootstrap.min.css
misc/vendor.sh https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.8/js/bootstrap.bundle.min.js
misc/vendor.sh https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.13.1/font/bootstrap-icons.min.css
misc/vendor.sh https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.13.1/font/fonts/bootstrap-icons.woff2 fonts/bootstrap-icons.woff2
misc/vendor.sh https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.13.1/font/fonts/bootstrap-icons.woff fonts/bootstrap-icons.woff
misc/vendor.sh https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js qrcode.js
```
