# The GCP OmniWitness

The OmniWitness is a witness that will monitor all [known](../../omniwitness/logs.yaml) logs that use
the [generic checkpoint format](https://github.com/transparency-dev/formats/tree/main/log).

The OmniWitness is opinionated on which logs and distributors will be used, and it is envisioned that eventually all productionized logs will use the generic checkpoint format and be witnessed by the OmniWitness.

The recommended way to deploy the OmniWitness is using this omniwitness binary, which is
a single executable that bundles all of the components. Instructions for deploying this are expanded below.

## Running in Docker

1. Copy the `docker-compose.yaml` file from this directory to your local filesystem, e.g. `/etc/omniwitness/docker-compose.yaml`
1. Create a `.env` file in this new directory, populated as described in [configuration](#configuration)
1. From that directory, run `docker compose up -d`

### .env File

The `.env` file required for the Docker service is a key-value format with this template:

```
WITNESS_PRIVATE_KEY_PATH=./path/to/private_key_in_vkey_format

WITNESS_VERSION=latest
```

`WITNESS_PRIVATE_KEY` should be generated as documented in [Witness Key Generation](#witness-key-generation).

## Running without Docker

If you prefer to run the OmniWitness outside of Docker, you can run the binary directly and pass in the configuration via flags.

### Simple

The simplest possible configuration brings up the OmniWitness to follow all of the logs,
but the witnessed checkpoints will not be distributed and can only be discovered via the
witness HTTP endpoints.
You will need to have followed the steps in [Witness Key Generation](#witness-key-generation).

```
go run github.com/transparency-dev/witness/cmd/omniwitness@main --alsologtostderr --v=1 \
  --private_key_path ./path/to/private_key_in_vkey_format \
  --db_file ~/witness.db
```


## Configuration

All deployments will need a keypair for signing/verifying witnessed checkpoints.
Most deployments should push the witnessed checkpoints to the distributors.
Instructions are provided for generating the material needed to do this.

Take care to protect any private material!

### Witness Key Generation

It is strongly recommended to generate new key material for a witness. This key
material should only be used to sign checkpoints that have been verified to be
an append-only evolution of any previously signed version (or TOFU in the case
of a brand new witness).

You'll need an ID/name for your witness. This should be a schemaless-URL which
uniquely identifies the witness, and be under a domain you control.

A keypair can be generated using the `cmd/generate_keys` tool in this repo.

### Public witness network support

The omniwitness supports automatic provisioning of logs via the public witness network.
More information about this network is available at https://witness-network.org.

The `--public_witness_config_url` flag may be provided multiple times to configure
one or more lists from the public witness network site/repo. The omniwitness will
periodically fetch these lists and provision any newly added logs to the local
configuration.

The interval between auto-provisioning attempts can be controlled with the 
`--public_witness_config_poll_interval` flag.

### Bastion Support

For operators who do not want to directly expose the witness API to the internet,
ths witness implementation supports the [bastion](https://github.com/C2SP/C2SP/blob/main/https-bastion.md)
protocol, allowing the witness to be reached via a compatible bastion proxy.

To enable this, two flags must be passed to `omniwitness`:

1. `--bastion_addr` is the `host:port` of the bastion host to connect to.
1. `--bastion_key_path` is the path to a file containing an ed25519 private key in PKCS8 PEM format.

To run the witness in bastion-only mode, set the `--poll_interval` flag to 0.
This will disable all attempts to poll logs, and witnessing will only occur via bastion connections.

Although the witness key _could_ be reused, it's strongly recommended to use a separate key for this. Such a key can be generated with the following command:

```bash
openssl genpkey -algorith ed25519 -out ./my_bastion_private_key.pem
```

The bastion host operator will need to be given the hash of the corresponding public key bytes in order to provision the witness.

The `omniwitness` prints this value out when it starts up:

```text
I0522 11:16:31.889534  758297 bastion_feeder.go:56] My bastion backend ID: 02b2442688cd1728f5c25c8425d69a915daddcfa4eb28a809a6b144b0ba889f3
```

Alternatively, the hash can be obtained with the following command:

```bash
$ openssl pkey -in ./my_bastion_private_key.pem -pubout -outform der | tail -c32 | sha256sum
02b2442688cd1728f5c25c8425d69a915daddcfa4eb28a809a6b144b0ba889f3  -
```

## Testing

### Interactively

You can use the [`/cmd/feedwitness`](/cmd/feedwitness) command to fetch checkpoints and send them to your
witness instance by running the following command:

```
# Change the --witness_url value to point to your witness instance if necessary
go run github.com/transparency-dev/witness/cmd/feedwitness@main --alsologtostderr --witness_url=http://localhost:8080
```

### Passively 

If all is well then after a few minutes you should see information printed in the logs of the above command
about checkpoints being witnessed.

If you've set up a REST distributor correctly, you should also see the witnessed checkpoints being pushed
there too.
