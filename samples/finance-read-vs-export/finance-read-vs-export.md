# Sample 8: Finance Read vs Export

## Goal

Separate broad read access from tightly controlled export access.

## Scenario

- Team: 900
- Users: analyst, manager, intern
- Permissions:
  - finops.read
  - finops.export

## Setup

- analyst: allow finops.read
- manager: allow finops.read and finops.export
- intern: allow finops.read then deny finops.export

## Checks

- analyst read: true, export: false
- manager read: true, export: true
- intern read: true, export: false (deny wins)
