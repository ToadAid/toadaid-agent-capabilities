# D2 — Capability-specific package surfaces

D2 keeps one `@toadaid/agent-capabilities` package while separating public
consumer entrypoints by capability family.

## Public surfaces

The package declares explicit subpaths for:

- `policy`
- `invocation`
- `contracts`
- `modules`
- `host-session`
- `desktop-observation`
- `desktop-interaction`
- `host-services`
- `browser-runtime`

The implementation-facing modules remain internal. Small facade modules under
`src/surfaces/` define the stable package boundary and re-export the exact value
and type families intended for each consumer.

## Browser dependency boundary

`playwright-chromium` is no longer a normal runtime dependency. It is an
optional peer dependency used only by the explicit `browser-runtime` surface
and remains a development dependency so the repository can build and test that
surface.

A host-only install of the package therefore does not install Playwright.
Consumers that need browser execution install the exact compatible
`playwright-chromium` peer.

The broad root export is retained for alpha compatibility. Host/provider
consumers should use the capability-specific subpaths instead of the root
surface.

## Permanent package proof

`npm run package:check` now proves:

1. every declared export maps to built JavaScript and declaration files;
2. every package subpath self-imports successfully in the repository build;
3. host-only D2 surfaces have no transitive JavaScript or declaration path into
   browser runtime implementation files or `playwright-chromium`;
4. `browser-runtime` is the explicit graph that owns the Playwright dependency;
5. a packed artifact installed into a clean temporary host consumer does not
   install Playwright;
6. that clean host consumer can import every host D2 runtime surface and resolve
   every host D2 type surface.

This is a package boundary, not a new authority layer. Importing a narrower
surface never grants capability authority.
