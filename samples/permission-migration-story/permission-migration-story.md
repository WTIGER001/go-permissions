# Sample 14: Permission Migration Story

## Goal

Demonstrate a safe migration from an old permission ID to a new permission ID using temporary dual grants.

## Scenario

- User: legacy-user
- Team: 808
- Old permission: reports.read
- New permission: reports.view

## Migration Steps

1. Existing grant with old permission only.
2. Add dual grant with new permission.
3. Update application checks to new permission.
4. Remove old grant after transition (simulated as optional note).

## Expected Checks

- Before dual grant: old=true, new=false
- After dual grant: old=true, new=true
