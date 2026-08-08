- **`@id` annotations name policies in decision reasons.** A model that annotates a
  policy with `@id("F-money")` gets that name in `reasons` and in `decern explain`,
  instead of a position that shifts when a policy is added; duplicate names refuse to
  load. A model without annotations keeps the positional ids it always had — the
  builtin model is unchanged. Authored by @anivar.
