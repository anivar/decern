- **A caller bound to itself can no longer assert `consent` or `human_approved`.** Under the
  signed-request, SPIFFE and AAuth postures a workload not listed in `--pep` may name only
  itself, and may not describe a party through `properties`; it could still send
  `"consent": true` in `context`, which the consent gate read as the resource owner's word. An
  evaluation or a search from such a caller that carries either key, whatever its value, is
  now refused with `403 caller_mismatch` and nothing is recorded; a batch is refused whole when
  any item, or a default an item inherits, carries one. This holds where the key was dropped
  before: `human_approved` on an action that does not declare it, and either key under a
  Mission, which used to be stripped. Such a workload therefore has no way to carry consent,
  and its access to another party's PII is always denied. A PEP listed in `--pep`, a bearer
  caller and a trusted front may carry the keys as before: `consent` is still the caller's
  word, which decern does not check. The rule knows these two names only; a custom model that
  reads an approval under another name is not covered. Authored by @anivar.
