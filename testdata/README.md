# Vulnerable examples

One file per rule, with real-looking workflows that are **vulnerable on purpose**: run octoscan against them to see
what a rule reports. Do not copy them.

```
./octoscan scan testdata                       # everything
./octoscan scan testdata/prompt-injection.yml  # one rule
```

Each file starts with the command to run and the number of findings it must have (`# expect: <rule>=<n>`). The comments
explain every case. `go test ./core -run TestVulnerableExamples` checks that the examples still find what they say, and
that every rule has a file.

| File | Needs |
|---|---|
| `repo-jacking.yml` | Internet (the owners of the actions are looked up on github.com) |
| `shellcheck.yml` | `shellcheck` in the PATH |
| `debug-artefacts.yml`, `debug-js-exec.yml`, `debug-oidc-action.yml` | `--debug-rules` |
| `debug-external-trigger-*.yml` | `--debug-rules --filter-triggers external` |

Scanning the whole folder reports more than the `expect` of a file: the workflows trip other rules too, the number is for the
rule of the file.
