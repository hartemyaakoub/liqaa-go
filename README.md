<div align="center">

# LIQAA Go SDK

**Server-side Go client for the LIQAA Public API.**

[![go reference](https://pkg.go.dev/badge/github.com/hartemyaakoub/liqaa-go.svg)](https://pkg.go.dev/github.com/hartemyaakoub/liqaa-go)
[![go report](https://goreportcard.com/badge/github.com/hartemyaakoub/liqaa-go?style=flat-square)](https://goreportcard.com/report/github.com/hartemyaakoub/liqaa-go)
[![go version](https://img.shields.io/badge/go-%3E%3D1.21-00add8?style=flat-square)](https://golang.org)
[![license](https://img.shields.io/badge/license-MIT-475569.svg?style=flat-square)](./LICENSE)

[Website](https://liqaa.io) · [Docs](https://liqaa.io/docs) · [JS SDK](https://github.com/hartemyaakoub/liqaa-js)

</div>

---

## Install

```bash
go get github.com/hartemyaakoub/liqaa-go
```

Zero dependencies (stdlib `net/http` + `crypto/hmac`). Go 1.21+.

## Quick start

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/hartemyaakoub/liqaa-go"
)

func main() {
    client := liqaa.New(os.Getenv("LIQAA_PK"), os.Getenv("LIQAA_SK"))
    ctx := context.Background()

    // 1) Identity → 1-hour browser-safe JWT
    tok, err := client.ExchangeSDKToken(ctx, liqaa.Identity{
        Email: "user@example.com",
        Name:  "Anonymous Visitor",
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Println("sdk_token:", tok.SDKToken)

    // 2) Create persistent room
    conv, err := client.CreateConversation(ctx, liqaa.ConversationCreate{
        CallerEmail:            "agent@yoursite.com",
        CalleeEmail:            "customer@example.com",
        ExternalConversationID: "ticket-42",
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Println("join_url:", conv.JoinURL)
}
```

## Webhook verification (`net/http`)

```go
import "github.com/hartemyaakoub/liqaa-go"

verifier := liqaa.NewWebhookVerifier(os.Getenv("LIQAA_WEBHOOK_SECRET"))

http.HandleFunc("/webhooks/liqaa", func(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)
    if !verifier.Verify(body, r.Header.Get("X-LIQAA-Signature")) {
        http.Error(w, "invalid signature", http.StatusUnauthorized)
        return
    }
    // event verified — handle here
    w.WriteHeader(http.StatusNoContent)
})
```

## License

[MIT](./LICENSE) © TKAWEN — LIQAA Cloud.
