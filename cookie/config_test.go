package cookie

import (
	"context"
	"fmt"
	"testing"
)

func TestConfig(t *testing.T) {

	ctx := context.Background()

	cfg, err := NewConfig(ctx, "https://example.com/?name=test&ttl=PT1H&samesite=strict")

	if err != nil {
		t.Fatal(err)
	}

	ck, err := cfg.NewCookie(ctx, "testing")

	if err != nil {
		t.Fatal(err)
	}

	// test=testing; Path=/; Domain=example.com; Expires=Sat, 03 Oct 2020 18:29:10 GMT; Secure; SameSite=Strict

	fmt.Println(ck.String())
}
