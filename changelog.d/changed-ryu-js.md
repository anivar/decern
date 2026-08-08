- **Number digits come from `ryu-js`**, Ryu adapted to ECMAScript's own rules — which is what
  RFC 8785 §3.2.2.3 defers to, and the generator the maintained JCS crates use. Output is
  unchanged: still byte-identical to V8 across 3.1M doubles. Authored by @anivar.
