# Sample 12: Service Account Automation

## Goal

Model a non-human account with narrow automation permissions.

## Scenario

- Service account: svc-billing-sync
- Team: 77
- Permissions:
  - billing.jobs.run
  - billing.jobs.read

## Setup

- Allow svc-billing-sync run and read for team 77.
- No grants outside team 77.

## Checks

- run on team 77: true
- read on team 77: true
- run on team 88: false
