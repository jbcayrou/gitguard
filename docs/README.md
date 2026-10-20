Source of the project page, built by GitHub Pages (Jekyll) from this
directory: Settings → Pages → Source: *Deploy from a branch*, folder `/docs`.

Layout:

- `index.md` — the whole text of the page, in Markdown. Sections are thin
  `<section id="…" markdown="1">` wrappers so that the nav anchors and the
  stylesheet keep working; the few coloured terminal samples are
  `{% capture %}` blocks handed to the `term` include.
- `_data/attacks.yml` — the five attacks of the demo (story and terminal
  lines); `_data/gitdir.yml` — the gitdir diagram; `_data/nav.yml` — the
  header links.
- `_includes/` — `hero`, `term` (a terminal window), `lines` (terminal lines
  from a data list), `attacks` (the tabs, rendered from the data),
  `gitdir-tree`.
- `_layouts/default.html`, `assets/css/style.css`, `assets/js/demo.js` (tab
  switching only), `assets/logo.png` — the theme.

Local preview, with the Debian packages (`jekyll`, `ruby-jekyll-seo-tag`):

```sh
cd docs && jekyll serve      # http://127.0.0.1:4000/gitguard/
```

or with the `github-pages` gem: `bundle exec jekyll serve`.
