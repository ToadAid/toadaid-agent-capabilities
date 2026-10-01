# P16B observation evidence semantics

P16B makes live desktop evidence precise enough to support safe downstream interaction.

Every observation now binds the selected provider descriptor, provider generation, and evidence namespace. Window heads and element references carry the same identity, and the runtime resolves the current provider identity before accepting them. A provider restart or namespace change therefore invalidates old live references even when the window ID has not changed.

Numeric display IDs are scoped by an exact display-topology epoch. Requests using display indexes must carry that epoch, adapters must return the same epoch, and P17 coordinate targets must bind it again. Display indexes are not treated as durable monitor identities.

Exact-window UI observations carry bounded geometry with an explicit `DESKTOP_PHYSICAL` or `WINDOW_CLIENT_PHYSICAL` coordinate space. P17 requires the target to use the same space and remain inside those bounds. Desktop-physical display targets additionally bind the selected display ID and topology epoch.

`WAIT_FOR` accepts both positive matches and bounded timeouts. The receipt records `MATCHED` or `TIMED_OUT` together with `NOT_REQUESTED`, `REQUESTED`, `DELIVERED`, `CONFIRMED_QUIESCENT`, or `UNCERTAIN` cancellation truth. A wait is refused before provider entry unless its maximum wall-clock duration fits inside the remaining P15 lease lifetime.
