# Sample 6: Who-Has Audit Report

## Goal

Generate a small audit view of principals that hold permissions across scopes.

## Scenario

- Team: 3003
- Permissions:
  - billing.invoice.read
  - billing.invoice.approve

## Data

- user: auditor-1 -> billing.invoice.read
- group: finance-reviewers -> billing.invoice.read
- role: role.approver -> billing.invoice.approve
- deny: role.approver denied billing.invoice.approve for object invoice-locked

## Output

Print principal hits for:

1. billing.invoice.read (team 3003)
2. billing.invoice.approve on object invoice-123 (team 3003)
3. billing.invoice.approve on object invoice-locked (team 3003)

## Expected

- Read report shows user/group owners.
- Approve on invoice-123 shows role.approver.
- Approve on invoice-locked excludes role.approver due to deny.
