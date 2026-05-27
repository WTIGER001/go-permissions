# Samples

Each sample should live in its own folder and include exactly two files:

1. `<name>.md` for the scenario description, assumptions, and expected outcomes.
2. `main.go` for executable sample code.

## Naming Convention

Use kebab-case folder and markdown names, for example:

- `deny-overrides-allow/deny-overrides-allow.md`
- `deny-overrides-allow/main.go`

## Suggested Markdown Structure

- Goal
- Setup Data
- Checks to Run
- Expected Results
- Notes

## Suggested Go Structure

- Seed data for the sample scenario.
- Run one or more permission checks.
- Print or assert expected outputs.
