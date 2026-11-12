# Diagrams

The docs diagrams are drawn with archify (github.com/tt-a1i/archify, MIT). Each `*.archify.json`
here is the source; the explorable page and the light and dark SVG exports in web/public/diagrams
are generated from it and are not edited by hand.

- architecture.archify.json: the system from the public sources to the console, shown on /docs and
  /docs/architecture.
- sync.archify.json: how the API loads its data, as a sequence, shown on /docs/adr-0007. Each
  participant cites the lines of the repository that carry its part, at the revision in its meta.

To redraw one, from the repository root, with archify installed and Chromium on the path given in
ARCHIFY_CHROME:

    node <archify>/bin/archify.mjs finalize architecture docs/diagrams/architecture.archify.json \
      web/public/diagrams/architecture.html --quality showcase --json
    node <archify>/bin/archify.mjs finalize sequence docs/diagrams/sync.archify.json \
      web/public/diagrams/sync.html --repo-root . --quality showcase --json

The finalize run validates the source, renders the page, checks it, and loads it in a real browser.
The SVG files come from the page's Export menu (SVG, Light and SVG, Dark), saved as
`<name>-light.svg` and `<name>-dark.svg`. The delivery receipt finalize writes beside the page holds
local paths, so it is not committed.
