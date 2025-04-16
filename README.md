# Witness

[![Go Reference](https://pkg.go.dev/badge/github.com/transparency-dev/witness.svg)](https://pkg.go.dev/github.com/transparency-dev/witness)
[![Go Report Card](https://goreportcard.com/badge/github.com/transparency-dev/witness)](https://goreportcard.com/report/github.com/transparency-dev/witness)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/transparency-dev/witness/badge)](https://securityscorecards.dev/viewer/?uri=github.com/transparency-dev/witness)
[![Slack Status](https://img.shields.io/badge/Slack-Chat-blue.svg)](https://transparency-dev.slack.com/)

## Overview

This repository contains libraries and binaries for running witnesses.
A witness verifies that logs are evolving in an append-only manner and counter-signs checkpoints that represent an append-only evolution from any previously witnessed checkpoints.
These witnessed checkpoints can be consumed by clients that want protection against split-views.

Users wishing to run this should start with the [OmniWitness](./cmd/omniwitness/).

## Importance of Witnesses

Some important terminology:

Term                | Definition
--------------------|------------
Log                 | A verifiable data structure that commits to a list of entries
Append Only         | New entries added to a log can only be added to the end of the list
Checkpoint          | A Checkpoint is a _signed_ commitment to the state of a Log at a given size
Split View          | A split view is a situation where a Log presents two views of its data where one is not a prefix of the other
Consistency Proof   | A crytographic proof between two checkpoints that proves one of them is an Append Only evolution of the other
Witness             | Tracks one or more logs, verifying Consistency Proofs to ensure it cannot cross any Split Views

Witnesses are a critical part of a secure transparency ecosystem by providing an anchor that guards against split view attacks by log operators.

A log that could successfully perform a split view would be able to show one list of entries to users that rely on the data (e.g. malware), and a different list of data to the verifiers of this data (e.g. only good builds of software).

This fundamentally undermines the main property of logs: _discoverability_.
Discoverability ensures that any data that is relied upon by one user will eventually be discovered and verified by someone that is holding the claimant and the log to account.
See https://transparency.dev/how-to-design-a-verifiable-system/ for information on the Claimant Model, which succinctly describes roles in a transparency ecosystem.


A Witness keeps a single Checkpoint for each log in secure storage.
On first initialization, this Checkpoint may come from the Log and be Trusted On First Use (TOFU).
Thereafter:
 1. The witness acquires a new Checkpoint and a Consistency Proof from its previous state
 2. This Consistency Proof is verified, and if the new Checkpoint is confirmed to be Append Only from the previous one, it updates its state
 3. The new Checkpoint is countersigned by the Witness, and made available to the public

A feature of [Checkpoints](https://c2sp.org/tlog-checkpoint) is that they allow multiple signatures to be added.
This means that a common way to see Checkpoints in a witnessed ecosystem is with a log signature first, and then multiple witness signatures.
An example witnessed checkpoint is:

```
developers.google.com/android/binary_transparency/0
611
2GZ1zmS5VkfUZmn2ZyR4KZXwHLD+xnwBIWzql/cD50w=

— pixel_transparency_log csh42zBFAiAd3Y1FwqNTt5RglY0uG7heC6Yu1gEbXXPYmZ7LdOILMAIhAIt68PnR/3TADAaC7hvrSHbpziV7TmpIwOUydLmcjyTQ
— ArmoredWitness-small-breeze nRq5UQAAAABnoqrsRIofXn68vTohcAm2KG4ACGyRPNePUk02BSWD0WKV5ElejTk5Z+Tm3GmJ5j/etA+fkL9XuaQsnTyZbr437sF4AQ==
— ArmoredWitness-autumn-wood qZb5XQAAAABnoqrl57G9CblEl3lwwuqzbaJvVMqNiZCbYZseYT1YZHYmls3CmT1wxZ1fNgM4RxHuUxjAwcI2ghTx6R5aCg+L0DGPBA==
```

See also the [distributor](https://github.com/transparency-dev/distributor) project, which makes available witnessed checkpoints from the [Armored Witness](https://github.com/transparency-dev/armored-witness), a dedicated hardware device that runs the witness code from this repository.

## API

The witness is an HTTP service that stores checkpoints it has seen from
different verifiable logs in a sqlite database.  This is a very lightweight way
to help detect or even prevent split-view attacks.

The witness provides three API endpoints (as defined in [api/http.go](api/http.go)):
- `/witness/v0/logs` returns a list of all logs for which the witness is
  currently storing a checkpoint.
- `/witness/v0/logs/<logid>/update` acts to update the checkpoint stored for 
  `logid`.
- `/witness/v0/logs/<logid>/checkpoint` returns the latest checkpoint for
  `logid`, signed by the witness.

## Running the witness

Most users wanting to run a witness will simply deploy the [OmniWitness](cmd/omniwitness),
which is preconfigured to witness all known logs using the checkpoint format.

## Support
* Mailing list: https://groups.google.com/forum/#!forum/trillian-transparency
- Slack: https://transparency-dev.slack.com/ ([invitation](https://join.slack.com/t/transparency-dev/shared_invite/zt-27pkqo21d-okUFhur7YZ0rFoJVIOPznQ))
