# CarnotEngine

Carnot Engine eBPF correlation & metrics prototype.

## Overview

This consolidated repository merges the Deepthink kit with runnable scaffolding (agents, CLI, attest, merge, proxy, integrations) to prototype runtime-to-BOM correlation using eBPF, plus policy and assessment tooling.

Key implemented item:
- OpenSSL handshake correlation (TID-keyed) emitting aggregated JSON lines with SNI, groups, success flag, and metrics (eventsReceived, handshakesEmitted, correlationTimeouts, cacheEvictions, kernel_drops).

See `WORKLOG.md` and `COPILOT/` tasks for incremental progress and guidance.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE` file for details.
