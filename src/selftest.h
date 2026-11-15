#pragma once

// Headless integration self-test (`radius --selftest`).
// Spins up real Kademlia nodes and real Noise/Double-Ratchet sessions
// over loopback UDP/TCP — no mocking. Returns process exit code.
int run_selftest();
