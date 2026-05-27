# Sample 5: Registry-First Grant Validation

## Goal

Show how a permission registry can reject invalid permission IDs before grants are written.

## Scenario

- User: ops-user
- Permission ID attempted first: finops.system.typo (invalid)
- Valid permission ID: finops.system.report.view

## Steps

1. Create an empty registry.
2. Attempt to grant an unknown permission and fail fast.
3. Register the valid permission definition.
4. Grant again and succeed.
5. Verify permission check returns true.

## Expected Outcome

- First grant attempt fails with validation error.
- Second grant attempt succeeds.
- `HasSystemPermission` returns true for ops-user.
