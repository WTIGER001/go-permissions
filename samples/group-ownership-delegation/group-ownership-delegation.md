# Sample 9: Group Ownership Delegation

## Goal

Delegate group membership management only for owned groups.

## Scenario

- User: lead-1
- Groups: group-a, group-b
- Permission: groups.members.manage

## Setup

- Allow lead-1 manage members on group-a object only.
- No grant for group-b.

## Checks

- lead-1 can manage group-a: true
- lead-1 can manage group-b: false
