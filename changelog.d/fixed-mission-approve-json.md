- **A malformed Mission approval is refused in JSON.** `POST /mission/v1/approve` answered a body
  that is not an approval request in plain text. It now answers
  `{"error": "mission not approved", "detail": …}`, the shape of every other approval refusal,
  with 400 for JSON that does not parse, 422 for a missing or mistyped field, 415 without a JSON
  content type and 413 past the 2 MiB body limit. The detail quotes the request and is cut at 512
  characters.
  Authored by @anivar.
