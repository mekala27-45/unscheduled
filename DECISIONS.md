# Decisions

Dated, newest last. Every entry that set a window, a rule, a threshold or a name cites what it rests
on, with the date read.

## 2026-11-07: the setup is done by the build, with no typed secret

Ajay asked on 7 November that Claude do all of the setup, with all permissions granted. Two limits
hold even then: Claude never types a password, key or token into any field, and never creates an
account. So the database connection reaches Vercel only through the Neon integration, GitHub Actions
holds no database credential, the API pulls its data from the public release (ADR 0007, to come at
step nine), and the NVD fetch runs keyless in resumable chunks.

## 2026-11-07: the look comes from a dealt theme, not from an earlier build

Ajay said the earlier sites read alike. The hallmark skill dealt three themes for this product
(Blueprint, Cobalt, Coral); Cobalt was taken because it is made for developer and infrastructure
tools. Its faces were already used in the series, so the voice is kept with unused faces: Rethink
Sans, Anek Latin and Mononoki, each confirmed on npm on 7 November.

## 2026-11-07: the web project is named unscheduled, served at unscheduled-triage.vercel.app

unscheduled.vercel.app already belongs to another Vercel account (it served a calendar app when
checked on 7 November), so Vercel gave the project unscheduled-sigma.vercel.app. The production
domain was changed to unscheduled-triage.vercel.app, a free vercel.app name, and the old name
redirects to it with a 307. The API project is unscheduled-api at unscheduled-api.vercel.app.

## 2026-11-07: Neon project in us-east-1, linked to Vercel by the existing account

The Neon project unscheduled was created in the existing Neon account in AWS US East 1 (N.
Virginia), next to the Vercel default function region, on the free plan (1 GB of storage per
project as the create dialog stated on 7 November). It is linked to unscheduled-api through the
Neon integration for Vercel with Link Existing Neon Account, scoped to that one Vercel project. The
other option, Create New Neon Account, was not taken: the build never creates an account.
