# Readme

# V2 Endpoint
With the V2 REST API we started using a design driven process.

The API is defined using [OpenAPI v2](https://swagger.io/specification/v2/) in **algod.oas2.json**.

## Updating the V2 REST API

1. Document your changes by editing **algod.oas2.json**
2. Regenerate the endpoints by running **make generate**.
3. Update the implementation in **server/v2/handlers.go**. It is sometimes useful to consult **generated/\*/\*/routes.go** to make sure the handler properly implements **ServerInterface**.

### Adding a new V2 API
When adding a new endpoint to the V2 APIs, you will need to add `tags` to the path. The tags are a way of separating our
APIs into groups--the motivation of which is to more easily be able to conditionally enable and/or disable groups of
endpoints based on the use case for the node.

Each API in `algod.oas2.json`, except for some pre-existing `common` APIs, should have two tags.
1. Either `public` or `private`. This controls the type of authentication used by the API--the `public` APIs use the
`algod.token` token, while the `private` APIs use the admin token, found in `algod.admin.token` within the algod data
directory.
2. The type, or group, of API. This is currently `participating`, `nonparticipating`, `data`, or `experimental`, but
may expand in the future to encompass different sets of APIs. Additional APIs should be added to one of the existing
sets of tags based on its use case--unless you intend to create a new group in which case you will need to additionally
ensure your new APIs are registered.

For backwards compatibility, the default set of APIs registered will always be `participating` and `nonparticipating`
APIs.

The current set of API groups and some rough descriptions of how to think about them:
* `participating`
  * APIs used in forming blocks/transactions and generally advancing the chain. Things which use the txn pool,
participation keys, the agreement service, etc.
* `nonparticipating`
  * Generally available APIs used to do things such as fetch data. For example, GetGenesis, GetBlock, Catchpoint Catchup, etc.
* `data`
  * A special set of APIs which require manipulating the node state in order to provide additional data about the node state
at some predefined granularity. For example, SetSyncRound and GetLedgerStateDelta used together control and expose StateDelta objects
containing per-round ledger differences that get compacted when actually written to the ledger DB.
* `experimental`
  * APIs which are still in development and not ready to be generally released.

## What codegen tool is used?

We found that [oapi-codegen](https://github.com/deepmap/oapi-codegen) produced the cleanest code, and had an easy to work with codebase. There is an algorand fork of this project which contains a couple modifications that were needed to properly support our needs.

Specifically, `uint64` types aren't strictly supported by OpenAPI. So we added a type-mapping feature to oapi-codegen.

## Why do we have algod.oas2.json and algod.oas3.yml?

We chose to maintain V2 and V3 versions of the spec because OpenAPI v3 doesn't seem to be widely supported. Some tools worked better with V3 and others with V2, so having both available has been useful. To reduce developer burden, the v2 specfile is automatically converted v3 using [converter.swagger.io](http://converter.swagger.io/).

If you want to run the converter locally, you can build the [swagger-converter](https://github.com/swagger-api/swagger-converter) project or run its [docker image](https://hub.docker.com/r/swaggerapi/swagger-converter) and specify the `SWAGGER_CONVERTER_API` environment variable when using this Makefile, for example by running:
```
SWAGGER_CONVERTER_API=http://localhost:8080 make
```
