package main

import (
	"regexp"
	"testing"
)

func TestObservationUsesVersionedAllowList(t *testing.T) {
	value := collect()
	if value.SchemaVersion != "v1" {
		t.Fatalf("unexpected schema version %q", value.SchemaVersion)
	}
	if _, ok := value.Facts["os"]; !ok {
		t.Fatal("OS facts are required")
	}
	if _, ok := value.Facts["collector"]; !ok {
		t.Fatal("collector provenance is required")
	}
}

func TestIdempotencyKeyIsUUID(t *testing.T) {
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if value := randomID(); !pattern.MatchString(value) {
		t.Fatalf("not a version 4 UUID: %q", value)
	}
}

func TestStatusUIRejectsNonLoopbackBind(t *testing.T) {
	if err := serveUI([]string{"--listen", "0.0.0.0:17654"}); err == nil {
		t.Fatal("non-loopback status UI bind was accepted")
	}
}
