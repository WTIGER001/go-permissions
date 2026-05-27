# Sample 3: Hierarchical Folders and Files

## Goal

Demonstrate object-scoped permissions for a hierarchical file system where file objects are represented as:

`<file>/<folder>/<workspace>`

This sample uses one permission:

- folders.file.read
  - Scope: object
  - Meaning: can read file contents for a specific file path object

## Actors

- Users: alice, bob, carol
- Role: role.finance_folder_reader

## Hierarchy

- Workspace: workspace-acme
- Folders:
  - folder-finance
  - folder-engineering
- Files:
  - file-budget (in folder-finance)
  - file-payroll (in folder-finance)
  - file-roadmap (in folder-engineering)

## Setup

### Direct grants

- alice allow read on:
  - file-budget/folder-finance/workspace-acme
  - file-payroll/folder-finance/workspace-acme

### Role grants

- role.finance_folder_reader allow read on:
  - file-budget/folder-finance/workspace-acme
  - file-payroll/folder-finance/workspace-acme

### Role assignment

- bob assigned role.finance_folder_reader

### Deny override

- role.finance_folder_reader deny read on:
  - file-payroll/folder-finance/workspace-acme

## Expected Checks

1. alice can read budget in finance: true
2. alice can read payroll in finance: true
3. bob can read budget in finance: true
4. bob can read payroll in finance: false (deny override)
5. carol can read budget in finance: false
6. bob can read roadmap in engineering: false

## Who-Has Checks

1. Who has folders.file.read on budget path:
- should include user alice and role.finance_folder_reader

2. Who has folders.file.read on payroll path:
- should include user alice
- should exclude role.finance_folder_reader because deny overrides allow for that principal and object

## Notes

- The sample uses `ObjectPermission.CanHierarchical` for ergonomic checks.
- Field-level filtering is intentionally out of scope.
