# Sample 1: Group Manager Roles

## Goal

Model a simple group management lifecycle that grows over time:

1. Start with users and groups.
2. Add system permissions for creating groups and viewing group names.
3. Add a group-scoped permission for managing membership.
4. Add a reusable group manager role and assign it to users.

## Actors and Groups

- Users: user1, user2, user3, user4
- Groups: group1, group2, group3, group4

## Permission Definitions

- groups.create
  - Scope: system
  - Meaning: can create groups
- groups.view.name
  - Scope: system
  - Meaning: can view group names
- groups.members.manage
  - Scope: object
  - Meaning: can add and remove members for a specific group object

## Build-Up Phases

### Phase 1: System-level permissions

Seed direct grants:

- user1: groups.create
- user1: groups.view.name
- user2: groups.view.name

Checks:

- user1 can create groups: true
- user2 can create groups: false
- user2 can view group names: true

### Phase 2: Group-scoped management permission

Simulate creating a new group group5 and grant user1 group-specific management rights:

- user1: groups.members.manage on object group5

Checks:

- user1 can manage members for group5: true
- user1 can manage members for group2: false

### Phase 3: Group manager role

Define role role.group_manager and grant:

- role.group_manager: groups.members.manage on object group5

Assign role to:

- user3
- user4

Checks:

- user3 can manage members for group5: true
- user4 can manage members for group5: true
- user2 can manage members for group5: false

## Notes

- This sample uses object scope for group-level management by setting object to the group ID.
- The who-has query is principal-based and returns grant owners (for example user and role owners), not expanded user membership through roles.
- Field-level filtering is intentionally out of scope for this sample.
