# Sample 11: Regional Compliance Fence

## Goal

Apply a deny fence over broad allow permissions.

## Scenario

- User: analyst-global
- Permission: datasets.view
- Objects: region-us, region-eu, region-restricted

## Setup

- Allow datasets.view globally to analyst-global
- Deny datasets.view for object region-restricted

## Checks

- region-us: true
- region-eu: true
- region-restricted: false
