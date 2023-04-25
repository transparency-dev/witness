# Witness

[![Go Report
Card](https://goreportcard.com/badge/github.com/transparency-dev/witness)](https://goreportcard.com/report/github.com/transparency-dev/witness)
[![GoDoc](https://godoc.org/github.com/transparency-dev/witness?status.svg)](https://godoc.org/github.com/transparency-dev/witness)
[![Slack
Status](https://img.shields.io/badge/Slack-Chat-blue.svg)](https://gtrillian.slack.com/)

## Overview

This repository contains libraries and binaries for running witnesses.
A witness verifies that logs are evolving in an append-only manner and counter-signs checkpoints that represent an append-only evolution from any previously witnessed checkpoints.
These witnessed checkpoints can be consumed by clients that want protection against split-views.

Users wishing to run this should start with the [OmniWitness](./cmd/omniwitness/).

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
* Slack: https://gtrillian.slack.com/ (invitation)
