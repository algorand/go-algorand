## Manual deploy steps

It's **very** important that the docker container is run **before** the `release-page` **and** the `docker-hub` `mule` tasks in `package-deploy`.

The docker container will do the following (see the `create_and_push` shell script):

1. Copy the new `algorand` and `algorand-devtools` packages from the `algorand-staging` to `algorand-internal` buckets so the `packages/` directory in the container will be properly synced with the `algorand-internal` bucket.

1. Sync `algorand-internal/packages` -> `packages/` in the container.

1. Add the deb packages to the appropriate `aptly` repo.

1. Create the snapshot (naming convention is `CHANNEL-VERSION`).

1. Switch out the old snapshot in the `algorand-releases/deb` location for this new one.

1. Sync `algorand-staging` -> `algorand-dev-deb-repo`

When that is finished, it is safe to run the following commands (order doesn't matter):

- `mule -f package-deploy releases-page`
- `mule -f package-deploy docker-hub`

> Note that the releases page is built from the latest release in the `algorand-dev-deb-repo` bucket, hence the need to have first run the docker container which performs that sync operation.

