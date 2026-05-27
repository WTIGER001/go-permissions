# Sample 10: Break-Glass Admin

## Goal

Demonstrate emergency access role plus deny guardrails.

## Scenario

- User: oncall-admin
- Role: role.break_glass
- Permission: incidents.resolve

## Setup

- role.break_glass allow incidents.resolve
- assign role.break_glass to oncall-admin
- explicit deny on oncall-admin for incidents.resolve on object incident-42

## Checks

- oncall-admin can resolve incident-41: true
- oncall-admin can resolve incident-42: false
