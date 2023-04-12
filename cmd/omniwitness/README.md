# The OmniWitness

The OmniWitness is a witness that will monitor all [known](../../omniwitness/feeder_configs/) logs that use
the [generic checkpoint format](https://github.com/transparency-dev/formats/tree/main/log).

The OmniWitness is opinionated on which logs and distributors will be used, and it is envisioned that eventually all productionized logs will use the generic checkpoint format and be witnessed by the OmniWitness.

The recommended way to deploy the OmniWitness is using this omniwitness binary, which is
a single executable that bundles all of the components. Instructions for deploying this are expanded below.

## Running in Docker

1. Copy the `docker-compose.yaml` file from this directory to your local filesystem, e.g. `/etc/omniwitness/docker-compose.yaml`
1. Create a `.env` file in this new directory, populated as described in [configuration](#configuration)
1. From that directory, run `docker compose up -d`

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

A keypair can be generated using `note.GenerateKey`; example code is provided
at https://play.golang.org/p/uWUKLNK6h9v. It is recommended to copy this code
to your local machine and run from there in order to minimize the risk to the
private key material.

### GitHub Credentials

This is optional, but recommended in order to push your checkpoints to as wide
an audience as possible and strengthen the network.
Checkpoints will be pushed to the distributors using GitHub pull requests.
This means that GitHub credentials must be provided.
It is strongly recommended to set up a dedicated account for this purpose.

GitHub setup:
  * Create a personal access token with `repo` and `workflow` permissions at https://github.com/settings/tokens
  * Fork both of the repositories:
    * https://github.com/mhutchinson/mhutchinson-distributor
    * https://github.com/WolseyBankWitness/rediffusion

Raise PRs against the distributor repositories in order to register your new
witness in their configuration files. Documentation on how to do this is found
on the README at the root of these repositories.

### .env File

The `.env` file required for the Docker service is a key-value format with this template:

```
WITNESS_PRIVATE_KEY=PRIVATE+KEY+YourTokenHere+XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
WITNESS_PUBLIC_KEY=YourTokenHere+01234567+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

GITHUB_AUTH_TOKEN=ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
GIT_USERNAME=johndoe
GIT_EMAIL=johndoe@example.com

WITNESS_VERSION=latest
```

`WITNESS_PRIVATE_KEY` and `WITNESS_PUBLIC_KEY` should be generated as documented in [Witness Key Generation](#witness-key-generation).

If you wish to use the distributors to push to GitHub, follow the steps in [GitHub Credentials](#github-credentials) and then:
  * The token should be set as `GITHUB_AUTH_TOKEN`
  * `GIT_USERNAME` is the GitHub user account
  * `GIT_EMAIL` is the email address associated with this account

## Running without Docker

If you have some reason to run the OmniWitness outside of Docker, then you can run the binary directly and pass in the configuration via flags.

### Simple

The simplest possible configuration brings up the OmniWitness to follow all of the logs,
but the witnessed checkpoints will not be distributed and can only be disovered via the
witness HTTP endpoints.
You will need to have followed the steps in [Witness Key Generation](#witness-key-generation).

```
go run github.com/transparency-dev/witness/cmd/omniwitness@master --alsologtostderr --v=1 \
  --private_key PRIVATE+KEY+my.witness+67890abc+xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --public_key my.witness+67890abc+xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --db_file ~/witness.db
```

### Full

A more advanced configuration for users that are committed to running the witness is to
set up witnessed checkpoints to be distributed via the GitHub distributors, which will
strengthen the ecosystem. Note that this requires more configuration of GitHub secrets,
and your witness key adding to the configuration files for the distributors.
This is described in [GitHub Credentials](#github-credentials).

```
go run github.com/transparency-dev/witness/cmd/omniwitness@master --alsologtostderr --v=1 \
  --private_key PRIVATE+KEY+my.witness+67890abc+xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --public_key my.witness+67890abc+xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --gh_user my-github-user \
  --gh_email foo@example.com \
  --gh_token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --db_file ~/witness.db
```

## Testing

If all is well then after a few minutes you should be able to see witnessed checkpoints locally:

```
# List all of the known logs
curl -i http://localhost:8100/witness/v0/logs
# Take a look at one of them
curl -i http://localhost:8100/witness/v0/logs/bdc0d5078d38fc2b9491df373eb7c0d3365bfe661c83edc89112fd38719dc3a0/checkpoint
```

If you set up the distributors correctly, then you should see pull requests being raised against the GitHub distributors.
