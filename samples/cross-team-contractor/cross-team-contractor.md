# Sample 7: Cross-Team Contractor

## Goal

Model one contractor with access to only selected teams.

## Scenario

- User: contractor-1
- Teams: 11, 22, 33, 44
- Permission: tasks.view

## Setup

- Allow contractor-1 on team 11
- Allow contractor-1 on team 33
- No grants for teams 22 and 44

## Checks

- team 11: true
- team 22: false
- team 33: true
- team 44: false

## Note

This pattern is common for temporary cross-functional access.
