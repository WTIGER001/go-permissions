# Sample 13: Tenant Onboarding Kit

## Goal

Show a reusable team role bundle assigned during tenant onboarding.

## Scenario

- New team: 555
- User: tenant-admin
- Role: role.tenant_starter
- Permissions:
  - projects.view
  - projects.create

## Setup

- role.tenant_starter grants projects.view and projects.create with team_scope ?team
- assign role.tenant_starter to tenant-admin with binding team=555

## Checks

- tenant-admin view on team 555: true
- tenant-admin create on team 555: true
- tenant-admin view on team 777: false
