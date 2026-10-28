- **`/audit/v1/subject` says `truncated` only when a record about the party was left out.** The
  projection stops at 256 records, and it reported the cut as soon as any later record existed,
  so exactly 256 records about a party followed by records about anyone else read as cut. It now
  reports the cut only when a further record names the same handle; a list the bound fits
  exactly is complete.
  Authored by @anivar.
