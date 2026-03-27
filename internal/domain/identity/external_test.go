package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewExternalIdentity_Valid(t *testing.T) {
	ei, err := NewExternalIdentity("ei1", "p1", "ext-sub", "int-sub", "t1")

	require.NoError(t, err)
	assert.Equal(t, "ei1", ei.ID)
	assert.Equal(t, "p1", ei.ProviderID)
	assert.Equal(t, "ext-sub", ei.ExternalSubject)
	assert.Equal(t, "int-sub", ei.InternalSubject)
	assert.NotNil(t, ei.ProfileData)
	assert.False(t, ei.LinkedAt.IsZero())
}

func TestNewExternalIdentity_EmptyID(t *testing.T) {
	_, err := NewExternalIdentity("", "p1", "ext", "int", "t1")
	require.Error(t, err)
}

func TestNewExternalIdentity_EmptyProviderID(t *testing.T) {
	_, err := NewExternalIdentity("ei1", "", "ext", "int", "t1")
	require.Error(t, err)
}

func TestNewExternalIdentity_EmptyExternalSubject(t *testing.T) {
	_, err := NewExternalIdentity("ei1", "p1", "", "int", "t1")
	require.Error(t, err)
}

func TestNewExternalIdentity_EmptyInternalSubject(t *testing.T) {
	_, err := NewExternalIdentity("ei1", "p1", "ext", "", "t1")
	require.Error(t, err)
}
