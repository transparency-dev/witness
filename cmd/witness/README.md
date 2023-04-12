# Witness

This executable is intended for users that need to run a witness for a log that is not covered by the [OmniWitness](../omniwitness/).
A good use-case for this may be a new log that is being developed.
It is envisioned that all productionized logs will be tracked by the OmniWitness, so long-term use of this witness for a log is an anti-pattern.

## Running

Invoke `go run main.go` with the following flags:
- `listen`, which specifies the address and port to listen on.
- `db_file`, which specifies the desired location of the sqlite database.
- `config_file`, which specifies configuration information for the logs. A
  sample configuration file is at `example_config.yaml`, and in general it
  is necessary to specify the following fields for each log:
    - `logID`, which is the identifier for the log.
    - `origin`, which is the expected first line of the checkpoint from this log.
    - `pubKey`, which is the public key of the log.  Given the current reliance on the Go [note format](https://pkg.go.dev/golang.org/x/exp/sumdb@v0.0.2/internal/note), the witness supports only Ed25519 signatures.
    - `hashStrategy`, which is the way in which recursive hashes are formed in the verifiable log.  The witness currently supports only `default` for this field.
    - `useCompact`, which is a boolean indicating if the log proves consistency via "regular" consistency proofs, in which case the witness stores only the latest checkpoint in its database, or via compact ranges, in which case the witness stores the latest checkpoint and compact range.
- `private_key`, which specifies the private signing key of the witness.  Again,
  the witness currently supports only Ed25519 signatures.
