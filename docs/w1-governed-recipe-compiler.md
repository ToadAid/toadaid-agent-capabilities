# W1 — Governed Recipe Compiler

W1 turns a declarative workflow recipe into a bounded execution plan without giving the recipe any authority of its own.

Compilation is deterministic planning, not execution. P3 remains the source of current capability authority, and a compiled plan is evidence/state rather than a permission token.

## Recipe shape

A governed recipe declares:

- recipe ID and version
- bounded parameters with scalar schemas and optional defaults
- a bounded response schema
- maximum turns
- maximum retries
- required capabilities
- optional capabilities
- forbidden capabilities
- ordered capability-bound steps

Capability roles are disjoint. A capability cannot appear in more than one of required, optional, or forbidden.

## Compile law

`compileGovernedRecipe()` resolves every declared capability through the current P3 manifest and policy chain.

- required capability BLOCK or unknown -> compilation fails closed
- optional capability ALLOW -> enabled
- optional capability BLOCK or unknown -> its steps become `SKIPPED_OPTIONAL`
- forbidden capability -> never enters the effective capability set, even if ambient policy currently allows it

Every step must use a capability explicitly declared required or optional. Required steps use `onUnavailable=FAIL`; optional steps use `onUnavailable=SKIP`.

The recipe cannot self-authorize a capability by naming it.

## Parameters and response schema

Parameters support bounded string, boolean, and safe-integer values. Parameters may be required or may provide a validated default. Undeclared input fields are refused.

The response schema supports the same scalar types plus a bounded flat object with explicit properties and required fields. Undeclared response fields are refused.

This is intentionally a small data schema surface rather than an executable validation language.

## Turn and retry bounds

Recipes carry explicit runtime ceilings:

- `maxTurns`: 1..256
- `maxRetries`: 0..16

These values are plan bounds only. They do not grant model, tool, host, or network authority.

## Plan integrity and current authority

The normalized recipe is SHA-256 fingerprinted. The compiled plan is also SHA-256 sealed over its canonical plain-data representation.

`assertGovernedRecipePlanCurrent()` must be called before execution or resume. It rechecks every capability that the compiled plan intends to use.

If an enabled capability has been revoked since compilation, execution refuses.

If an optional capability was unavailable during compilation but becomes allowed later, the existing plan stays skipped. New authority never silently widens an old plan; the recipe must be compiled again to adopt it.

The plan hash is tamper evidence, not authorization. Current P3 checks remain authoritative.

## P4/P5 composition

The embedding runtime can use the compiled plan to seed P4/P5 execution state:

- recipe identity and plan hashes become provenance/evidence
- enabled steps become bounded pending work
- skipped optional steps remain explicit
- the P4 authority snapshot remains historical evidence only
- a P5 child receives no capability outside the compiled effective capability set and its current delegated P3/P5 authority

W1 does not directly create child tasks or execute steps. It compiles the bounded workflow surface before those runtime actions occur.

## Non-authority

W1 does not execute tools, invoke models, materialize secrets, mutate repositories, browse the web, restore workspaces, or approve economic actions.

A recipe is a declaration. A compiled plan is a declaration checked against current policy. The runtime must still perform fresh authority checks at the point of action.
