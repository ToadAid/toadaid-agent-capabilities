# P19 provider selection, availability, and health

P19 makes provider routing a live, host-bound projection rather than treating module enablement as proof that an implementation can execute now.

The projection keeps five truths separate: `KNOWN` catalog entries, `INSTALLED` built-ins and non-removed modules, `ENABLED` built-ins and enabled modules, host-compatible providers with current health (`AVAILABLE_HEALTHY` or `AVAILABLE_DEGRADED`), and capabilities independently `AUTHORIZED` by P3. Health never grants authority.

Each sealed health report binds the exact module lifecycle head, provider descriptor, adapter registration, implementation fingerprint, host/session lease identity, provider generation, observation window, status, and optional evidence digest. Missing, expired, incompatible, or explicitly unavailable providers project as `UNAVAILABLE` with a typed reason.

Selection occurs after platform and health filtering. One compatible provider may be selected directly; multiple compatible providers fail closed until an exact lifecycle-bound selection is supplied. An explicit selection never silently fails over to another implementation.

The availability-bound runtime registry retains the projection SHA and provider generation. Provider disappearance, degradation, restart, module disable/removal, host-session change, or selection change produces a different projection and makes the prior runtime registry unusable.
