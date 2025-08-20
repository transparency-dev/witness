# OmniGCP

This binary is a GCP-native and opinionated version of the generic `omniwitness` binary, which uses:
- Cloud Spanner for storing the witness state, and
- Secret Manager for storing the witness key.

## Running

### Prerequisites

#### Spanner database

There must already be a Cloud Spanner instance and database created.
This database instance should not have any DDL applied (i.e. there should be no tables present - the binary will create the tables itself).
Take note of the resource name for this database, it'll be of the format `projects/{projectName}/instances/{instanceName}/databases/{databaseName}`.

#### Secret Manager

There must already be a Secret Manager secret created which contains a note-formatted Ed25519 signing key.
You'll need the resource name for the initial version of this secret , it'be of the format `projects/{project_id}/secrets/{secret_name}/versions/1`

Such a signing key can be generated using the following command:

```bash
export WITNESS_NAME=example.com/example-witness
go run github.com/transparency-dev/serverless-log/cmd/generate_keys@HEAD --key_name="${WITNESS_NAME}" --print
```

Note that we *only* need the signing key here, `omniwitness` is able to derive the corresponding public key at runtime from the secret key.

### Starting the witness

You can run this binary directly on a GCP VM like so:

```bash
export SPANNER="projects/..." # This is the spanner resource name of the existing database.
export SECRET="projects/..." # This is the secret manager secret name.
go run ./cmd/gcp/omniwitness/ --signer_private_key_secret_name=${SECRET} --spanner=${SPANNER}
```

