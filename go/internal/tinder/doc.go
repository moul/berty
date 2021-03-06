package tinder

// Tinder service is a multi-driver service backed by a cache
//
//                   ┌───────────────────────────────────────────────────┐
//                   │ Tinder                                            │        ┌───────────────────────┐
// ┌───────────────┐ │                                                   │  ┌────▶│    Driver DHT Ipfs    │
// │   Advertise   │▶┼───┐     ┌────────────────┐                        │  │     └───────────────────────┘
// └───────────────┘ │   │     │ Backoff Cache  │                        │  │     ┌───────────────────────┐
// ┌───────────────┐ │   ├────▶│    Discover    │──┐   ┌───────────────┐ │  ├────▶│   Driver DHT Berty    │
// │   FindPeers   │▶┼───┘     └────────────────┘  │   │Driver Manager │ │  │     └───────────────────────┘
// └───────────────┘ │              ┌──────────────┴──▶│ (MultiDriver) │─┼──┤     ┌───────────────────────┐
// ┌───────────────┐ │              │                  └───────────────┘ │  ├────▶│Driver RendezVousPoint │
// │  Unregister   │▶┼──────────────┘                                    │  │     └───────────────────────┘
// └───────────────┘ │                                                   │  │     ┌───────────────────────┐
//                   │                                                   │  └────▶│Driver Local (ble/mdns)│
//                   └───────────────────────────────────────────────────┘        └───────────────────────┘
