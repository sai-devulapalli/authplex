package sms

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConsoleSender_SendOTP(t *testing.T) {
	sender := NewConsoleSender(slog.Default())

	err := sender.SendOTP(context.Background(), "+1234567890", "123456")

	assert.NoError(t, err)
}
