# Limitations

Known scope cuts in v0.1 of the agent-sandbox daemon. These are deliberate and documented so operators understand what the sandbox does and does not protect against. v0.2 may revisit any of these; until then, the policy here is "ship the limitation, document it, do not silently work around it."

## DNS rotation

The daemon resolves `manifest.allowed_hosts` exactly once, at agent launch, via `net.LookupHost`. Each resolved IP becomes its own allow entry in the BPF policy map. If a host's authoritative DNS rotates after the agent starts — common for CDNs, cloud load balancers, and any service behind a short-TTL record — the agent will keep dialing the IPs captured at launch. New IPs the host migrates to are not in the map and will be blocked, which manifests to the agent as a connection refusal. There is no DNS-rebinding protection either: if a hostname resolves to a benign IP at launch and a malicious one mid-run, the daemon never re-checks. Operators who need fresher resolution must restart the agent; integrating a DNS-aware enforcement plane is a v0.2 design question, not a v0.1 bug.

## IPv4 / IPv6 family handling

Each resolved address from `net.LookupHost` becomes its own entry — a single `example.com` typically yields one IPv4 entry and one IPv6 entry, both allowed. The kernel-side enforcement uses two separate maps (one keyed by `__u32` for `connect4`, one keyed by `__u8[16]` for `connect6`); the agent's libc picks which family to dial via Happy-Eyeballs (RFC 8305) and the daemon does not steer that choice. Side effect: if you list a hostname whose v4 record is allowed-by-policy but whose v6 record is not, the agent may connect over v6 first and you have to allow both records or strip one at the resolver. Listing a literal IP entry binds only that family.

## TCP only in v0.1

Only TCP outbound (`IPPROTO_TCP`, proto=6) is enforced. UDP, SCTP, ICMP, and raw sockets pass through unfiltered because the v0.1 BPF programs hook only `cgroup/connect4` and `cgroup/connect6`, which fire on stream-style connect calls. This means DNS over UDP (port 53), QUIC/HTTP3, WireGuard, mDNS, and any custom UDP protocol are unrestricted — an agent that wants to exfiltrate over UDP can do so. Agents that only speak HTTPS over TCP are fully covered; anything else is not. UDP enforcement is a v0.2 task and requires either a `cgroup_skb` egress program (which is byte-level and harder to write a clean policy for) or distinct hooks for each socket type.
