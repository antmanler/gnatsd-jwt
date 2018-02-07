# gnatsd-jwt
NATS server with a  simple jwt auth backend

## Try it

### Using cfssl generate certs

```shell
$ cfssl gencert -initca ca-csr.json | cfssljson -bare ca -
$ cfssl gencert -config config.json -profile signing -ca ca.pem -ca-key ca-key.pem sign-csr.json | cfssljson -bare sign
```

### Start server

```shell
go run main.go -D --jwt_publickey testdata/sign.pem
```

### Sign JWT tokens

*User Admin*

```json
{
    "user": "admin",
    "permissions": {
        "publish": [
            ">"
        ],
        "subscribe": [
            ">"
        ]
    }
}
```

*User Req*

```json
{
    "user": "req",
    "permissions": {
        "publish": [
            "req.foo",
            "req.bar"
        ],
        "subscribe": [
            "_INBOX.*.*"
        ]
    }
}
```

*Generate tokens*

```shell
$ ADMIN_TOKEN=$(cat testdata/admin.json | go run $GOPATH/src/github.com/dgrijalva/jwt-go/cmd/jwt/*.go -key testdata/sign-key.pem -alg ES256 -compact -sign -)
$ echo ${ADMIN_TOKEN}
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJwZXJtaXNzaW9ucyI6eyJwdWJsaXNoIjpbIlx1MDAzZSJdLCJzdWJzY3JpYmUiOlsiXHUwMDNlIl19LCJ1c2VyIjoiYWRtaW4ifQ.RYBsHJ4OGfvqzA2u9FOkb5oaaiiuLHKSjI4jzDN-kY9cD4yDrl0QHzI-e3E51-w9-2wJRGacdCFnizw95GrM8Q

$ REQ_TOKEN=$(cat testdata/req.json | go run $GOPATH/src/github.com/dgrijalva/jwt-go/cmd/jwt/*.go -key testdata/sign-key.pem -alg ES256 -compact -sign -)
$ echo ${REQ_TOKEN}
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJwZXJtaXNzaW9ucyI6eyJwdWJsaXNoIjpbInJlcS5mb28iLCJyZXEuYmFyIl0sInN1YnNjcmliZSI6WyJfSU5CT1guKi4qIl19LCJ1c2VyIjoicmVxIn0.7_w9gOtJH2RfaZPFMXeAANLLo_uGcCWwznRnhUFJ55_aAvqmPDeggmHQb1fTAn0gYO1j9RA0PM7oR6tmeD3-cQ
```

*Token for admin*

> eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJwZXJtaXNzaW9ucyI6eyJwdWJsaXNoIjpbIlx1MDAzZSJdLCJzdWJzY3JpYmUiOlsiXHUwMDNlIl19LCJ1c2VyIjoiYWRtaW4ifQ.RYBsHJ4OGfvqzA2u9FOkb5oaaiiuLHKSjI4jzDN-kY9cD4yDrl0QHzI-e3E51-w9-2wJRGacdCFnizw95GrM8Q

*Token for requestor*

> eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJwZXJtaXNzaW9ucyI6eyJwdWJsaXNoIjpbInJlcS5mb28iLCJyZXEuYmFyIl0sInN1YnNjcmliZSI6WyJfaW5ib3guXHUwMDNlIl19LCJ1c2VyIjoicmVxIn0.xzP29EnE97utwx19OT2Li2vpv3PEuWNgYWLwnFwPPckcnbjhTX2_GjMbMUqdmz8nxz0twkfjsKbAzwLgsLtt7g

```shell
# subscribe invliad topic using reqeuestor
$ go run $GOPATH/src/github.com/nats-io/go-nats/examples/nats-rply.go -s nats://${REQ_TOKEN}@127.0.0.1:4222 -t req.foo world
nats: permissions violation for subscription to "req.foo"
exit status 1

# subscribe using admin
$ go run $GOPATH/src/github.com/nats-io/go-nats/examples/nats-rply.go -s nats://${ADMIN_TOKEN}@127.0.0.1:4222 -t req.foo world
Listening on [req.foo]

# in another terminall, publish using requestor
go run $GOPATH/src/github.com/nats-io/go-nats/examples/nats-req.go -s nats://${REQ_TOKEN}@127.0.0.1:4222 req.foo hello
Published [req.foo] : 'hello'
Received [_INBOX.7w2XpYeWwiYRzR3aUri5aj.7w2XpYeWwiYRzR3aUri5fi] : 'world'
```