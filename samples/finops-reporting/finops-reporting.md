# Sample 2: FinOps Reporting

## Goal

Model two permission layers for FinOps reporting:

1. A system-wide reporting permission for global cost visibility.
2. A team-scoped reporting permission for team-level cost visibility.

This sample includes direct user grants and a role-based grant.

## Actors and Teams

- Users: alice, bob, carol, dave
- Teams: 101, 202, 303

## Permission Definitions

- finops.system.report.view
  - Scope: system
  - Meaning: can view system-wide cost reporting
- finops.team.report.view
  - Scope: team
  - Meaning: can view team-level cost reporting

## Scenario Setup

### Direct user grants

- alice: finops.system.report.view (team scope `*`)
- bob: finops.team.report.view for team 101

### Role-based grant

- Role: role.finops_team_reporter
- Role grant: finops.team.report.view for team 202
- Role assignment: role.finops_team_reporter -> carol

## Expected Checks

1. System-level checks
- alice can view system-wide report: true
- bob can view system-wide report: false

2. Team-level checks
- bob can view team 101 report: true
- bob can view team 202 report: false
- carol can view team 202 report: true
- carol can view team 303 report: false
- dave can view team 101 report: false

3. Who-has checks
- Who has system-wide report permission: should include user alice.
- Who has team 202 report permission: should include role.finops_team_reporter.

## Notes

- Team-scoped grants use `team_scope` with a concrete team ID string.
- The who-has query is principal-based and returns grant owners, not expanded user membership through assigned roles.
