<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog fragments

A change that a user would notice ships with its own entry, in this directory, in the same pull
request. `scripts/changelog.sh` assembles them into `CHANGELOG.md` at release and deletes them.

Writing the entry here rather than in `CHANGELOG.md` means it is written while the author still has
the context, it is reviewed alongside the code it describes, and two pull requests never conflict
over the same lines. It also survives a squash merge, which a commit message does not.

## Adding one

One file, named `<section>-<slug>.md`. The prefix picks the section, so nothing has to be parsed:

| Prefix | Section | For |
|---|---|---|
| `added-` | Added | something that was not there before |
| `changed-` | Changed | different behaviour, a different name, a different default |
| `fixed-` | Fixed | it did the wrong thing and now does the right thing |
| `security-` | Security | a reader running this needs to know |
| `removed-` | Removed | it is gone |
| `deprecated-` | Deprecated | it still works and will not |

The file holds the entry exactly as it should appear, starting with `- `. It is copied verbatim, so
it carries its own formatting:

```markdown
- **A tree head anyone can check.** `decern-serve` publishes a signed RFC 9162 tree head at
  `GET /anchor/v1/tree-head`, and `decern verify --anchor <file>` proves the log still extends a
  commitment published earlier — so a record dropped after it was committed is detectable by
  someone who is not the operator.
```

Write it for someone deciding whether this release affects them, not for the reviewer of the diff.
Lead with what it does; say where the guarantee stops if that is not obvious. The prose standard in
[`CONTRIBUTING.md`](../CONTRIBUTING.md) applies here too — no sentence beyond what carries meaning.

## Skipping one

A change with nothing for a user to notice does not need a fragment: a refactor, a test, a comment,
CI. Say so in the pull request and apply the `no-changelog` label; the check looks for that label
before it fails.

## Releasing

```bash
./scripts/changelog.sh --release 0.3.0
```

Folds every fragment into a new `CHANGELOG.md` section, dated today, and removes them. Review the
result before committing — assembly is mechanical, and the ordering within a section is only
alphabetical by filename.
