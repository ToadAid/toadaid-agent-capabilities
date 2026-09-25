# D1 — Package Distribution Surface

D1 makes `@toadaid/agent-capabilities` consumable through its declared package boundary instead of requiring source-path imports.

## Distribution contract

- The package remains private during the alpha forging phase.
- Git dependency installs run `npm run build` through the standard `prepare` lifecycle.
- Production build output is compiled with `tsconfig.build.json`, which includes `src/**/*.ts` and excludes repository tests.
- `files` allows only `dist/src` plus the README into the packed artifact. npm still includes its mandatory package metadata.
- Public imports are limited to the root package plus the declared capability infrastructure subpaths.
- Every exported JavaScript and declaration target must exist before a package is considered distributable.

## Package-boundary verification

`npm run package:check` performs a clean distribution build and then:

1. validates the export map and build/install scripts;
2. self-imports every public package specifier through Node's package self-reference rules;
3. runs `npm pack --dry-run --json --ignore-scripts`;
4. verifies every export target is present in the packed artifact; and
5. refuses source, test, docs, workflow, or packaging-script leakage.

This is a distribution check, not capability authority. Installing the package still grants zero P3 authority.

## Consumer model

During the private alpha phase, a governed agent may consume the repository as a Git dependency. `prepare` builds the package after dependencies are installed, so consumers receive the same `dist/src` entry points declared by the export map.

A later registry publication may remove `private: true` deliberately, but D1 does not publish, change access, or widen authority.

## Graduation boundary

D1 proves that the package surface is internally coherent. V1 remains responsible for the clean-room Agent0 vertical proof using the package as an external consumer rather than importing repository source files directly.
