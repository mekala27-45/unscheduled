# Diagrams

The docs diagrams are drawn with archify (github.com/tt-a1i/archify, MIT). Each `*.archify.json`
here is the source; the explorable page and the light and dark SVG exports in web/public/diagrams
are generated from it and are not edited by hand.

To redraw one, from the repository root, with archify installed and Chromium on the path given in
ARCHIFY_CHROME:

    node <archify>/bin/archify.mjs finalize architecture docs/diagrams/architecture.archify.json \
      web/public/diagrams/architecture.html --quality showcase --json

The finalize run validates the source, renders the page, checks it, and loads it in a real browser.
The SVG files come from the page's Export menu (SVG, Light and SVG, Dark).
