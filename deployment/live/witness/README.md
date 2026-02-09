# Witness deployment

The directories under here contain the top-level terragrunt files for the deployment environments.

In all cases, before deploying for the first time, you MUST have created the witness `private` key
and stored it in Secret Manager, or the `terragrunt apply` will fail.

> [!Note]
> While the witness binary itself doesn't need the `public` key, *you will* in order to share it
> with others.

Below is a `bash` snippet which will generate and store both the public and private key in Secret
Manager under secrets called `witness_public_XXX` and `witness_secret_XXX` respectively, where
```XXX``` is the name of the target deployment environment.

```bash
$ export TARGET="dev" # This MUST match the name of the directory you're deploying
$ export WITNESS_NAME="..." # This is the witness name we're generating keys for. It should follow the schemaless-url recommendation from `tlog-witness`.
$ go run github.com/transparency-dev/serverless-log/cmd/generate_keys@HEAD \
    --key_name="${WITNESS_NAME}" \
    --print | 
    tee >(grep -v PRIVATE | gcloud secrets create witness_public_${TARGET} --data-file=-) | 
    grep PRIVATE | 
    gcloud secrets create witness_secret_${TARGET} --data-file=- 
Created version [1] of the secret [witness_public_dev].
Created version [1] of the secret [witness_secret_dev].
```
