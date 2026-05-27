# Sample 4: Multi-Tenant Role Inheritance with Template Bindings

## Goal

Model a multi-tenant setup where inherited roles and template-bound grants provide team-specific permissions without creating separate role definitions per team.

## Actors

- Users: anna, ben, chris
- Teams: 1001, 2002
- Roles:
  - role.viewer (base role)
  - role.team_analyst (inherits role.viewer)

## Permission Definitions

- reports.view
  - Scope: team
  - Meaning: can view team reports
- reports.export
  - Scope: team
  - Meaning: can export team reports

## Role Graph

- role.team_analyst -> role.viewer (inheritance)

In this sample, we seed role expansion in the in-memory store to represent inherited descendants for `role.team_analyst`.

## Template Binding Strategy

Use a template team scope grant on role.viewer:

- owner: role.viewer
- permission: reports.view
- team_scope: ?team
- variable_spec: {"team": "required"}

When `role.team_analyst` is assigned to a user with binding values, the inherited role grant resolves to the assigned team.

## Scenario Setup

### Anna (team 1001 analyst)

- Assign role.team_analyst with binding: {"team": 1001}
- Role chain resolves inherited role.viewer grant for reports.view on team 1001

### Ben (team 2002 analyst)

- Assign role.team_analyst with binding: {"team": 2002}
- Role chain resolves inherited role.viewer grant for reports.view on team 2002

### Chris (direct export)

- Direct user grant reports.export on team 1001

## Expected Checks

1. anna can view reports for team 1001: true
2. anna can view reports for team 2002: false
3. ben can view reports for team 2002: true
4. ben can view reports for team 1001: false
5. chris can export reports for team 1001: true
6. chris can export reports for team 2002: false

## Notes

- This sample shows one reusable role model bound to different teams at assignment time.
- In-memory role expansion is configured via `SetRoleExpansion`.
- Who-has queries operate on stored grant owners and do not expand assignment bindings.
