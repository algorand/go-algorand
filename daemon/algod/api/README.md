# Readme

## Components:

- `swagger.json` defines the API schema. However, server code in `api/v1/...` 
currently serves as the ground truth, as the schema is generated from server code.
	- to generate `swagger.json`, run `make build`. You may need to have `go-swagger`
	installed. You can get it by running `make deps`.
- `api/client` is a package for internal (or external) libraries to interact with
 the REST API. In particular, it should minimize dependencies. 
    - we currently use a non-swagger generated client. Why? The swagger generated client
    pulls in too many dependencies (go-openapi, for instance) and unnecessary
    functionality. Testing the swagger spec must be done another way. It seems that 
    unwrapped json raw types are sent on the wire (so not wrapped by responses), 
    so we don't need to decode them into responses.
- `api/v1/...` contains an implementation for the server. The swagger schema is auto-generated 
(`cd api/; swagger generate spec -o ./swagger.json`) from server implementation code. 
`api/v1/handlers` and `api/v1/models` should never be directly imported by external clients.
    - or, run `go generate` in the `api` folder.
  

## Debugging/Engineering Notes:

- `go-swagger` does not generate `x-nullable` properties on model fields. We want them 
so that we can generate models without pointers. (This is more compatible with the 
current model we use. We may want to use pointers instead, eventually)
    - make sure you populate the `default` property in order to generate a model 
    without a pointer field
- `go-swagger` does not support OpenAPI 3.0. It only supports OpenAI 2.0. There 
does not seem to be another tool that allows us to generate a swagger spec from 
code. It may be worth writing our own, eventually.
- `go-swagger` does not support embedded structs.
    - in fact, `go-swagger` is generally very strange. The source -> spec generation
     looks fairly immature. Here are some (undocumented) tips:
        - every `swagger:response` type must contain a single field (e.g. `Body` or 
        `Payloard`) that is the actual data type you want to return. So the `response` 
        type is a wrapper, which makes sense, except the clients that `go-swagger`
         generate automatically unwrap the underlying value. So this is very weird, 
         and undocumented.
        - `swagger:route` is a less powerful version of the `swagger:operation` 
        annotation. 
        However, `swagger:operation` is much more finicky and not mature. When defining
         the annotation, make sure it is precise yaml, and start the yaml section with 
         `---`. This means keeping track of tabs and whitespaces. This seems to be the
          easiest way to define parameters without having to make explicit structs 
          (which we may want to do eventually anyways).
- don't deal with `go-swagger` codegen docs. Refer directly to 
`https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#pathItemObject`/
- `go-swagger` does not support `regex` in path parameter path templating.        
- complex parameter schemas are only supported in parameters `in:body`        
- responses are distinct from definition objects (e.g. the former has a`description` 
field, and headers). We always want to return a response in an operation. Returning 
a model seems to work, but does not seem advised.
- `go-swagger` assumes `x-isnullable: true` and generates pointer files. If we ever
want to use a swagger generated client internally this may be a problem. Note that
`go-swagger` doesn't support a corresponding `x-isnullable` annotation. We can get around
that by using the `default` annotation and then find-and-replacing an `x-isnullable` into
the actual spec:
```//go:generate sed -i "" -e "s/\"default/\"x-nullable\": false, \"default/" ./swagger.json
//go:generate sed -i "" -e "s/object\",/object\", \"x-nullable\": false,/" ./swagger.json
```
- go-swagger does not seem to support simple string responses. They always get wrapped. (oh well)
	e.g. [https://github.com/go-swagger/go-swagger/issues/1635]
- I've hardcoded a keylength into the spec for now, until I figure out how to tie that programatically
back into the server code (perhaps with a find-and-replace).