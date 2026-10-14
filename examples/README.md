# Examples

Two applications that receive security events from a Keycloak SSF transmitter, and one that mirrors
the users of a SCIM service provider from its SCIM Events, with a demo transmitter of its own. They
are the Go port of the [Spring Boot examples](https://github.com/easyssf/easyssf/tree/main/easyssf-receiver-spring-boot-examples)
of the Java library and use the same Keycloak realm. Not published: they live in the main module
for `go run`, nothing imports them.

| | Port | |
|---|---|---|
| [`keycloak/`](keycloak) | 8080 | Docker Compose setup: Keycloak 26.8 with the `ssf` feature and a pre-configured `ssf-demo` realm, the same files as in the Java and Rust repositories |
| [`resource-server/`](resource-server) | 8081 | OAuth2 resource server on `net/http`. Rejects access tokens once their Keycloak session was revoked. Has a `-poll` profile and a `-demo` mode against the in-process test transmitter. |
| [`oidc-client/`](oidc-client) | 8082 | Web application with OIDC login (by hand, in `oidc.go`). Ends the local session once the Keycloak session was revoked or the user's credentials changed. |
| [`scim-provisioning/`](scim-provisioning) | 8083 | Mirrors SCIM `Users` into a local directory from SCIM Events (RFC 9967). Runs without Keycloak, see [4.](#4-scim-provisioning) |

Neither Keycloak application contains SSF specific code apart from its receiver configuration (and
a handler in the resource server that logs the events): `receiver.New` assembles the receiver,
`rcv.PushHandler()` is the push endpoint, `receiver.RevocationMiddleware` and the session store
that implements `receiver.SessionTerminator` reject what the events revoked. What Spring Security
does for the Java examples is application code here: `auth.go` of the resource server validates
the access tokens, `oidc.go` of the OIDC client logs users in. Both manage their own stream: on
startup they authenticate with the service account of their Keycloak client and register a PUSH
stream for it (`Created SSF stream …`), after a restart they find it again (`Using existing SSF
stream …`). If you delete a stream in the admin console, the application creates a new one on its
next start.

## 1. Start Keycloak

```sh
cd examples/keycloak
docker compose up
```

- Admin console: <http://localhost:8080> (`admin` / `admin`), realm `ssf-demo`
- Users: `tester` / `test` and `bob` / `bob`

The database lives in `keycloak/data` and survives `docker compose down`; the realm is only
imported into an empty database, so delete `data/` to re-import `ssf-demo-realm.json`. The
clients are `example-resource-server`, `example-poll-receiver` and `example-oidc-client`, each
with a service account that may manage streams (`ssf.read`, `ssf.manage`) and the push URL of its
application in `ssf.validPushUrls`; `example-cli` is a public client for `curl`.

## 2. Resource server

```sh
go run ./examples/resource-server
```

```sh
KC=http://localhost:8080/realms/ssf-demo/protocol/openid-connect

# log in as tester and call the API
TOKENS=$(curl -s $KC/token -d grant_type=password -d client_id=example-cli -d username=tester -d password=test)
ACCESS_TOKEN=$(echo "$TOKENS" | jq -r .access_token)
REFRESH_TOKEN=$(echo "$TOKENS" | jq -r .refresh_token)

curl -i localhost:8081/api/me -H "Authorization: Bearer $ACCESS_TOKEN"    # 200

# end the session in Keycloak ...
curl $KC/logout -d client_id=example-cli -d refresh_token=$REFRESH_TOKEN

# ... the access token has not expired, but is rejected within a few seconds
curl -i localhost:8081/api/me -H "Authorization: Bearer $ACCESS_TOKEN"    # 401, error="invalid_token"
```

The log of the resource server shows the stream it registered on startup and the event:

```
msg="Created SSF stream" stream=d0200637-… delivery=urn:ietf:rfc:8935 endpoint=http://host.docker.internal:8081/ssf/push events=[CaepSessionRevoked] audience=[example-resource-server/d0200637-…]
msg="Received SET" jti=b639c4e1-… delivery=push events=[CaepSessionRevoked]
msg="revoked access tokens of session" event=CaepSessionRevoked session=hPB29fvO…
msg="Security event" event=CaepSessionRevoked user=33bf4f70-… session=hPB29fvO…
```

`GET /health` is the health of the receiver: its transmitter, stream and, with `-poll`, the poller
(503 when unhealthy). `KEYCLOAK_ISSUER`, `KEYCLOAK_CLIENT_SECRET` and `SSF_PUSH_URL` override the
defaults; `SSF_PUSH_URL` is how Keycloak in Docker reaches the application and must be allowed by
`ssf.validPushUrls` of the client.

### POLL delivery

With `-poll` the resource server does not register a PUSH stream for its own client. It
authenticates with the service account of the client `example-poll-receiver` instead, registers a
POLL stream for it and polls Keycloak for events every two seconds:

```sh
go run ./examples/resource-server -poll
```

```
msg="Created SSF stream" stream=ef50c4f3-… delivery=urn:ietf:rfc:8936 endpoint=http://localhost:8080/…/poll events=[CaepSessionRevoked] audience=[example-poll-receiver/ef50c4f3-…]
msg="Received SET" jti=52e22461-… delivery=poll events=[CaepSessionRevoked]
```

The `curl` commands work the same way. Keycloak keeps pushing to the PUSH stream of
`example-resource-server` in the meantime (streams survive a restart of the application), which
the application rejects in this profile.

### Without Keycloak

`go run ./examples/resource-server -demo` (also with `-poll`) runs the same application against
the in-process test transmitter: it registers its stream there, obtains an access token for
`alice`, prints the `curl` to call the API with it, then delivers one `session-revoked` SET for
her session, after which the same `curl` answers 401.

## 3. OIDC client

```sh
go run ./examples/oidc-client     # KEYCLOAK_ISSUER, KEYCLOAK_CLIENT_SECRET, SSF_PUSH_URL, BASE_URL override the defaults
```

Open <http://localhost:8082>, log in as `tester` / `test`. The page polls `/auth/check` every few
seconds. End the Keycloak session in the account console (or `docker compose exec keycloak
/opt/keycloak/bin/kcadm.sh` ... `delete sessions`), or change the password: Keycloak sends a SET
to `/ssf/push`, the receiver ends the local session (`receiver.WithSessionTerminator`), the page
notices. `SSF_PUSH_URL` is how Keycloak in Docker reaches the application,
`http://host.docker.internal:8082/ssf/push` by default; it must be allowed by `ssf.validPushUrls`
of the client `example-oidc-client` in the realm.

## 4. SCIM provisioning

```sh
go run ./examples/scim-provisioning                  # plays the life of two users
go run ./examples/scim-provisioning -autoplay=false  # starts with an empty directory
curl -s localhost:8083/users
```

Keycloak does not emit SCIM Events, so the application brings its own transmitter, the in-process
`ssftest.TestTransmitter`, and a demo SCIM service provider under `/demo/scim` that transmits a
SCIM Event for every request:

```sh
curl -s -X POST localhost:8083/demo/scim/Users -H 'Content-Type: application/json' \
  -d '{"userName": "carol", "externalId": "carol", "emails": ["carol@example.com"]}'
curl -s -X PATCH 'localhost:8083/demo/scim/Users/<id>' -H 'Content-Type: application/json' \
  -d '{"Operations": [{"op": "replace", "path": "displayName", "value": "Carol Davis"}]}'
curl -s -X PATCH 'localhost:8083/demo/scim/Users/<id>?mode=notice' ...   # a notice event, without data
curl -s -X POST localhost:8083/demo/scim/Users/<id>/deactivate
curl -s -X DELETE localhost:8083/demo/scim/Users/<id>
curl -s localhost:8083/demo/scim/events                                   # the SETs transmitted so far
```

The receiver polls the transmitter (`delivery-method: poll`, a stream it registers itself) and
`receiver.Scim(handler)` dispatches the events to `ScimProvisioningHandler`, which mirrors them into
the directory at `/users`. Against a real SCIM service provider, the receiver configuration in
`main.go` is all that changes.
