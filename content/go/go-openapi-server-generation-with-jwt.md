---
title: "Generate a Go Server with JWT Authorisation using OpenAPI 3"
date: 2022-02-27T10:30:00Z

categories: ['Go', 'Programming']
tags: ['Go', 'OpenAPI']
author: "jsfan"
featuredImage: "/images/openapi-go-jwt.jpg"
---

While the OpenAPI standard allows for defining [JWT authorisation for endpoints](https://swagger.io/specification/#components-security-schemes),
the Go server generator which is part of the [OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) does
not support that specification and will nto generate any JWT authorisation code.

However, despite the generator having a few limitations, most of the code generation comes down to processing [Mustache](https://mustache.github.io/)
templates which can be exported and modified. This post will go through the process of creating templates which introduce
selective JWT authorisation step by step.

To start with, you will need a copy of the OpenAPI generator. I'll assume in the post that you use the CLI, but you can
also set up a UI, of course. I will also assume that you use the [Docker image](https://hub.docker.com/r/openapitools/openapi-generator-cli)
for the CLI, but again it is up to you if you do that or rather install the CLI on your machine.

As mentioned above, it is possible to [export the default templates](https://openapi-generator.tech/docs/templating/#retrieving-templates),
so that's where we start:

    docker run --rm -v$(pwd)/api/templates:/out openapitools/openapi-generator-cli:v5.4.0 author template -g go-server

(Hint: You might want to run this as your local user using the `--user` flag, so the files generated aren't all owned by the root user.
Depending on your setup, you might also have to use `sudo docker` instead of just `docker`.)

For the version of OpenAPI Generator CLI, I'm using (v5.4.0), I get the following templates in `api/templates/`

    api.mustache
    controller-api.mustache
    Dockerfile.mustache
    error.mustache
    go.mod.mustache
    helpers.mustache
    impl.mustache
    logger.mustache
    main.mustache
    model.mustache
    openapi.mustache
    partial_header.mustache
    README.mustache
    routers.mustache
    service.mustache

Most of these files we will leave untouched. However, we will introduce new templates as well as modify some of these.
So, let's get started! If you don't want to follow along with all the modifications in detail, you can also find the
final version of the templates [in this GitHub repository](https://github.com/jsfan/openapi-go-jwt-templates). 

We will first have a look at the file `routers.mustache`. As the file name already indicates, this file contains the
router and alongside it also defines the routes that represent the endpoints of OpenAPI spec defines. As we want to some
of these endpoints to now require authorisation, we have to add another field to the struct that represents a route. That
struct looks something like this:

    // A Route defines the parameters for an api endpoint
    type Route struct {
            Name            string
            Method    string
            Pattern  string
            HandlerFunc http.HandlerFunc
    }

What we need to add is a flag that indicates that the route requires authorisation. So we change the struct to look like this:

    // A Route defines the parameters for an api endpoint
    type Route struct {
            Name            string
            Method    string
            Pattern  string
            HandlerFunc http.HandlerFunc
            AuthzRequired bool
    }

Next, we modify `controller-api.mustache` such that this flag is always included when routes are generated. What we are looking for
is a function that looks like this:

    // Routes returns all of the api route for the {{classname}}Controller
    func (c *{{classname}}Controller) Routes() Routes {
        return Routes{ {{#operations}}{{#operation}}
            {
                "{{operationId}}",
                strings.ToUpper("{{httpMethod}}"),
                "{{{basePathWithoutHost}}}{{{path}}}",
                c.{{operationId}},
            },{{/operation}}{{/operations}}
        }
    }{{#operations}}{{#operation}}

which we change to read like this instead:

    func (c *{{classname}}Controller) Routes() Routes {
        return Routes{ {{#operations}}{{#operation}}
            {
                "{{operationId}}",
                strings.ToUpper("{{httpMethod}}"),
                "{{{basePathWithoutHost}}}{{{path}}}",
                c.{{operationId}},
                {{#authMethods}}{{#isBasicBearer}}true,{{/isBasicBearer}}{{/authMethods}}{{^authMethods}}false,{{/authMethods}}
            },{{/operation}}{{/operations}}
        }
    }{{#operations}}{{#operation}}

Don't worry about the Mustache markers we use. These are all markers which are known to the generator and already in use
in other generators which do support authorisation.

We now have templates which distinguish between endpoints that have authorisation enabled and those that don't by passing
in our new boolean flag. If you wanted to handle your authorisation on every endpoint, you'd be done. However, we want
to validate JWTs centrally in a middleware and also skip the validation when an endpoint is hit that does not require
authorisation. So, we press on...

First off, we need to introduce some code which allows us to validate the JWT and send an HTTP code 401 if the JWT cannot
be validated. To that end, we create a new template file `api/templates/jwt.mustache` with the following content:

    {{>partial_header}}
    package {{packageName}}
    
    import (
            "gopkg.in/square/go-jose.v2"
            "gopkg.in/square/go-jose.v2/jwt"
            "time"
    )
    
    type JWTClaims map[string]interface{}
    
    // AuthErrorResponse is used when the authentication middleware rejects access.
    // This response should be aligned with the response your OpenAPI configuration assigns to the HTTP status code 401.
    type AuthErrorResponse struct {
            Message string
    }
    
    // ValidateClaims validates the token ensuring that it is not expired.
    // Add other expected values you want to validate as necessary.
    func ValidateClaims(claims *jwt.Claims, customClaims *JWTClaims) error {
            expected := jwt.Expected{
                    Time: time.Now(),
            }
    
            // TODO: Add check for custom claims as necessary.
    
            return claims.Validate(expected)
    }
    
    // Error401 returns the contents of the response to be sent when the middleware blocks access with status 401.
    // Message gives the reason why access was denied.
    func Error401(msg string) AuthErrorResponse {
            // TODO: Adapt to your own custom error response
            return AuthErrorResponse{
                    Message: msg,
            }
    }
    
    // SetKeys returns the key used for validating the JWT signatures.
    func SetKeys(env interface{}) (interface{}, error) {
        // TODO: Add your own logic for setting your keys.

        return &jose.JSONWebKeySet{}, nil
    }

As you can see, I'm using Square's JWT library. However, if you want to use a different library (e.g. the more recent
[fork of the Square library](github.com/go-jose/go-jose/v3) by the original author or [github.com/golang-jwt/jwt](https://github.com/golang-jwt/jwt))
you can just adapt the templates to work with your preference instead. As a word of warning though, you might want to avoid
`github.com/go-jose/go-jose/v2`. At the time of writing that package still pointed back to the original Square version
which might create types issues. If you do want to use it, you can try [my patch](https://github.com/go-jose/go-jose/pull/9)
which should solve these issues.

Now, we need to use the code we have introduced, so we create another file `api/templates/auth.mustache` which contains the
new authorisation middleware:

    {{>partial_header}}
    package {{packageName}}
    
    import (
        "context"
        "gopkg.in/square/go-jose.v2/jwt"
        "net/http"
        "strings"
    )
    
    type JWTLabel string
    
    const (
        authHeader = "Authorization"
        claimsContext JWTLabel = "JWT contents"
    
        NoToken = "No bearer token found."
        AuthorizationLineMalformed = "Authorization line was malformed."
        AuthorizationNotBearer = "No bearer token in authorization."
        JWTParseError = "JWT could not be parsed."
        SignatureInvalid = "JWT signature is invalid."
        ClaimsInvalid = "JWT claims are invalid."
    )
    
    // Auth is a middleware which validates a JWT and rejects unauthenticated access where appropriate.
    func Auth(inner http.Handler, keys interface{}, authRequired bool) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            bearerToken, ok := r.Header[authHeader]
            if !ok {
                if authRequired {
                    EncodeJSONResponse(Error401(NoToken), func(i int) *int { return &i }(http.StatusUnauthorized), w)
                    return
                }
                inner.ServeHTTP(w, r)
                return
            }
            tokenParts := strings.SplitN(bearerToken[0], " ", 2)
            if len(tokenParts) < 2 {
                EncodeJSONResponse(Error401(AuthorizationLineMalformed), func(i int) *int { return &i }(http.StatusUnauthorized), w)
                return
            }
            if strings.ToLower(tokenParts[0]) != "bearer" {
                EncodeJSONResponse(Error401(AuthorizationNotBearer), func(i int) *int { return &i }(http.StatusUnauthorized), w)
                return
            }
            token := tokenParts[1]
    
            parsedJWT, err := jwt.ParseSigned(token)
            if err != nil {
                EncodeJSONResponse(Error401(JWTParseError), func(i int) *int { return &i }(http.StatusUnauthorized), w)
                return
            }
            basicClaims := &jwt.Claims{}
            claims := &JWTClaims{}
            if err := parsedJWT.Claims(keys, &basicClaims, &claims); err != nil {
                EncodeJSONResponse(Error401(SignatureInvalid), func(i int) *int { return &i }(http.StatusUnauthorized), w)
                return
            }
    
            if err := ValidateClaims(basicClaims, claims); err != nil {
                EncodeJSONResponse(Error401(ClaimsInvalid), func(i int) *int { return &i }(http.StatusUnauthorized), w)
                return
            }
    
            ctx := context.WithValue(r.Context(), claimsContext, claims)
            inner.ServeHTTP(w, r.WithContext(ctx))
        })
    }

As you can see, the middleware primer allows us to pass in a boolean flag to distinguish between request which require
authorisation and those that don't. If the flag is `false`, our new middleware just passes on the request without doing
anything. If an `Authorization` header of type `Bearer` is found in the request, the middleware parses the JWT and
validates the claims. If they are found invalid, it sends an HTTP code 401 (`Unauhtorized`), otherwise it injects the
claims the code we added in the `jwt.mustache` template returned to the context and passes on the request.

You may have noticed that the code above does not handle `HTTP Basic` authentication or encrypted JWTs. However, you can
easily modify your templates to support that as well.

Now, we have a middleware that we can hook in the same way the templates already hook in the logging middleware. We go
back to `routers.mustache` and find the function `NewRouter()` which we add a parameter and a handler to:

    // NewRouter creates a new router for any number of api routers
    func NewRouter(keys interface{}, routers ...Router) {{#routers}}{{#mux}}*mux.Router{{/mux}}{{#chi}}chi.Router{{/chi}}{{/routers}} {
    {{#routers}}
            {{#mux}}
            router := mux.NewRouter().StrictSlash(true)
            {{/mux}}
            {{#chi}}
            router := chi.NewRouter()
            router.Use(middleware.Logger)
            {{#featureCORS}}
            router.Use(cors.Handler(cors.Options{}))
            {{/featureCORS}}
            {{/chi}}
    {{/routers}}
            for _, api := range routers {
                    for _, route := range api.Routes() {
                            var handler http.Handler
                            handler = route.HandlerFunc
                            handler = Auth(handler, keys, route.AuthzRequired)
    {{#routers}}
            {{#mux}}
                            handler = Logger(handler, route.Name)
                            {{#featureCORS}}
                            handler = handlers.CORS()(handler)
                            {{/featureCORS}}
    
                            router.
                                    Methods(route.Method).
                                    Path(route.Pattern).
                                    Name(route.Name).
                                    Handler(handler)
            {{/mux}}
            {{#chi}}
                            router.Method(route.Method, route.Pattern, handler)
            {{/chi}}
    {{/routers}}
                    }
            }
    
            return router
    }

The line we have added is this one:

    handler = Auth(handler, keys, route.Authenticated)

and because we need the keys here, we now have to pass those into `NewRouter()` as well.

Obviously, `NewRouter()` is called from somewhere, so we need to change the signature in the call as well. That call is
in `main()`. So, we change the line

    router := {{packageName}}.NewRouter({{#apiInfo}}{{#apis}}{{classname}}Controller{{^-last}}, {{/-last}}{{/apis}}{{/apiInfo}})

to

    var keyEnv interface{}
    keys, err := {{packageName}}.SetKeys(keyEnv)
    if err != nil {
        panic(err)
    }
    router := {{packageName}}.NewRouter(keys, {{#apiInfo}}{{#apis}}{{classname}}Controller{{^-last}}, {{/-last}}{{/apis}}{{/apiInfo}})

As you can see, we are using the function `SetKeys()` here which returns the keys to be used for validating the JWT.

At this point, we have the complete set of templates for adding JWT authorisation to our endpoints. The only thing left
to do make this work out of the box is to add the JWT package to the `go.mod.mustache`. If you have used the package
`gopkg.in/square/go-jose.v2` as suggested above, the `go.mod.mustache` needs to look something like this:

    module {{gitHost}}/{{gitUserId}}/{{gitRepoId}}
    
    go 1.13
    
    require gopkg.in/square/go-jose.v2 v2.5.1
    {{#routers}}
            {{#mux}}
    require github.com/gorilla/mux v1.7.3
                    {{#featureCORS}}
    require github.com/gorilla/handlers v1.5.1
                    {{/featureCORS}}
            {{/mux}}
            {{#chi}}
    require github.com/go-chi/chi/v5 v5.0.3
                    {{#featureCORS}}
    require github.com/go-chi/cors v1.2.0
                    {{/featureCORS}}
            {{/chi}}
    {{/routers}}

As a last bit of housekeeping, we change the `Dockerfile.mustache` adding the line

    COPY --from=build /etc/ssl/certs /etc/ssl/certs

which makes sure that any CA certificates which the JWT authentication may use are available within the Docker image.
For consistency, I've also updated the Go version, so the complete `Dockerfile.mustache` looks like this:

    FROM golang:1.13 AS build
    WORKDIR /go/src
    COPY {{sourceFolder}} ./{{sourceFolder}}
    COPY main.go .
    
    ENV CGO_ENABLED=0
    RUN go get -d -v ./...
    
    RUN go build -a -installsuffix cgo -o {{packageName}} .
    
    FROM scratch AS runtime
    COPY --from=build /go/src/{{packageName}} ./
    COPY --from=build /etc/ssl/certs /etc/ssl/certs
    EXPOSE 8080/tcp
    ENTRYPOINT ["./{{packageName}}"]

You may want to update the Go version to an even more recent version though.

So, now, we are really completely done with the code. There are only two things left to do which are

1. A config file for OpenAPI Generator CLI.
2. An OpenAPI spec file to test with.

The OpenAPI config file allows you to make a good number of settings. What we need is the
[settings for template customisation](https://openapi-generator.tech/docs/customization). We'll use an `openapi-generator.yml`
file that contains a few other settings as well to not have to specify them on the command line. You will have to change the
`gitRepoId` and `gitUserId` and may want to adapt some other settings as well. For details on the configuration options,
refer to the [official documentation](https://openapi-generator.tech/) and the OpenAPI Generator CLI's help.

    generatorName: go-server
    inputSpec: api/spec.yaml
    templateDir: api/templates
    gitUserId: change-this-to-your-github-account
    gitRepoId: change-this-to-your-repository-name
    additionalProperties:
      enumClassPrefix: false
      featureCORS: false
      hideGenerationTimestamp: true
      packageName: rest
      packageVersion: 0.0.1
      router: mux
      serverPort: 8080
      sourceFolder: go
    files:
      auth.mustache:
        destinationFilename: "go/auth.go"
      jwt.mustache:
        destinationFilename: "go/jwt.go"

As you can see, I'm already referencing the spec file. So, we now create that at `api/spec.yaml`. Again, we go with a
simple example:

    openapi: "3.0.3"
    info:
      description: "A test API for Go server with JWT"
      version: "0.0.1"
      title: "Test API"

    paths:
      /unauthenticated:
        get:
          operationId: "unauthenticated"
          summary: "An endpoint which does not require authentication."
          description: "Returns \"Hello World!\""
          responses:
            "200":
              description: "Hello World!"
              content:
                application/json:
                  schema:
                    $ref: "#/components/schemas/Message"
      /authenticated:
        get:
          operationId: "authenticated"
          summary: "An endpoint which does require authentication."
          description: "Returns \"Hello Authorised Citizens of the World!\""
          security:
            - JWTAuth: []
          responses:
            "200":
              description: "Hello Authorised Citizens of the World!"
              content:
                application/json:
                  schema:
                    $ref: "#/components/schemas/Message"
    
    components:
      schemas:
        Message:
          type: "object"
          properties:
            message:
              type: string
              example: "Hello World!"

        securitySchemes:
            JWTAuth:
              type: "http"
              scheme: "bearer"
To generate using the Docker image, you can run

    docker run --rm -v$(pwd):/src -w /src openapitools/openapi-generator-cli generate -c /src/openapi-generator.yaml

Theoretically, you can now run your server. However, the templates contain imports which are unused in the skeleton you have
at the moment. So, if you try to run or compile, you will get an error saying

    go/api_default.go:13:2: imported and not used: "encoding/json"
    go/api_default.go:17:2: imported and not used: "github.com/gorilla/mux"

Once you have removed those two imports from `go/api_default.go`, you probably want to run go fmt over it, make sure the `go.mod`
is ok and then run or build:

    gofmt -w .
    go mod tidy
    go run main.go

If you now open a browser and hit `http://localhost:8080/unauthenticated` (changing the port to whatever you used in the config file),
you'll get the response

    "Unauthenticated method not implemented"

If on the other hand you hit `http://localhost:8080/authenticated`, you get

    {"Message":"No bearer token found."}

which tells you that the authentication middleware blocked the request. A look at the development tools' network tab will
also show an HTTP status 501 for the unauthenticated route but an HTTP status 401 for the authenticated one.

If you want to make it easy to regenerate later on, you probably want to put the `*_service.go` files into the
`.openapi-generator-ignore` as the TODOs in the files suggest.
