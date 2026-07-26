---
icon: lucide/shield
---

# Security

zttp parses bytes that arrive straight off the network, which makes it a security
boundary. This page is the project's threat model: what zttp defends against,
what it deliberately leaves to you, and the residual risks.

!!! tip "Read the integrator responsibilities"
    zttp is sans-IO, so timeouts, connection concurrency, and tunnel handling are
    **yours**. The [Integrator responsibilities](#integrator-responsibilities)
    section below is the part most likely to bite a real deployment.

--8<-- "THREAT_MODEL.md"
