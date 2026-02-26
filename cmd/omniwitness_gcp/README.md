# OmniGCP

This binary is a GCP-native and opinionated version of the generic `omniwitness` binary, which uses:
- Cloud Spanner for storing the witness state & the set of known logs, and
- Secret Manager for storing the witness key.

## Log configuration

`OmniGCP` stores its configuration of known logs in a Spanner table. This allows the operator to add (or,
less likely, remove) logs by updating the table either directly via Spanner Studio, or using a tool.

Like the main `omniwitness` binary, `OmniGCP` also embeds the common list of known logs stored in this repo,
however this list is only used by `OmniGCP` to insert any previously unknown logs into the Spanner table
used as the canonical source of log information.

> [!NOTE]
> We're using *Secret Manager* as opposed to *Cloud KMS* - this means that the running binary has the witness
> secret key in memory while it's running. This is a trade off against the potentially quite high cost of
> Cloud KMS.
>
> From a risk point of view, if an adversary is able to compromise the running binary (or the host
> it's running on) in order to exfiltrate the secret key and use it to generate signatures for inconsistent
> checkpoints, they would also be able to use Cloud KMS as a signing oracle to do the same for as long as they
> retain access. 
> Either of these situations would be equally fatal for the trust in the witness.
>
> Nonetheless, it would be a relatively limited change to switch to using CloudKMS if desired.

## Running

### Prerequisites

#### Spanner database

There must already be a Cloud Spanner instance and database created. The amount of storage necessary should be tiny, since we only
store one checkpoint for each configured log. Similarly, even a Spanner instance with just 100 PU of CPU should be able to support
a large number of logs.

This database instance should not have any DDL applied (i.e. there should be no tables present - the binary will create the tables itself).

Take note of the resource name for this database, it'll be of the format `projects/{projectName}/instances/{instanceName}/databases/{databaseName}`.

#### Secret Manager

There must already be a Secret Manager secret created which contains a note-formatted Ed25519 signing key.

You'll need the resource name for the initial version of this secret , it'be of the format `projects/{project_id}/secrets/{secret_name}/versions/1`

The `cmd/generate_keys_gcp` tool in this repo will generate a new signing & verification key pair and store them directly in Secret Manager.

```bash
export WITNESS_SHORT_NAME=example-witness
export WITNESS_ORIGIN="<something including ${WITNESS_SHORT_NAME}"
go run github.com/transparency-dev/witness/cmd/generate_keys_gcp@HEAD \
   --origin="${WITNESS_ORIGIN}" \
   --resource_suffix="${WITNESS_SHORT_NAME}"
```

Note that while we *only* need the signing key to start the witness (`omniwitness_gcp` is able to derive the corresponding public key at runtime
from the secret key), having the public key stored somewhere is likely to be useful when you wish to publicise/share your witness' identity.

### Starting the witness

You can run this binary directly on a GCP VM like so:

```bash
export SPANNER="projects/..." # This is the spanner resource name of the existing database.
export SECRET="projects/..." # This is the secret manager secret name.
go run ./cmd/omniwitness_gcp/ --signer_private_key_secret_name=${SECRET} --spanner=${SPANNER}
```

