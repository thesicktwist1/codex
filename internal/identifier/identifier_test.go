package identifier

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_boolToString(t *testing.T) {
	// test with true
	expected := "1"
	got := boolToString(true)
	require.Equal(t, expected, got)
	// test with false
	expected = "0"
	got = boolToString(false)
	require.Equal(t, expected, got)
}

func Test_stringToBool(t *testing.T) {
	// "1" should be true
	expected := true
	got, err := stringToBool("1")
	require.NoError(t, err)
	require.Equal(t, expected, got)
	// "0" should be false
	expected = false
	got, err = stringToBool("0")
	require.NoError(t, err)
	require.Equal(t, expected, got)
	// anything else should be an error
	_, err = stringToBool("example")
	require.Error(t, err)
}

func Test_NewIdentifier(t *testing.T) {
	// well formed id
	id := "another:example:0"
	expected := &Identifier{
		Owner:    "another",
		Resource: "example",
		Private:  false,
	}
	got, err := New(id)
	require.NoError(t, err)
	require.Equal(t, expected, got)

	// no resource id
	id = "invalid::0"
	got, err = New(id)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEmptyField)

	// malformed id
	id = "another:example:0:field"
	_, err = New(id)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMalformed)

}

func Test_String(t *testing.T) {
	identifier := &Identifier{
		Owner:    "another",
		Resource: "example",
		Private:  false,
	}
	expected := "another:example:0"
	got := identifier.String()
	require.Equal(t, expected, got)

	identifier = &Identifier{
		Owner:    "",
		Resource: "example",
		Private:  false,
	}
	expected = ":example:0"
	got = identifier.String()
	require.Equal(t, expected, got)
}

func Test_Format(t *testing.T) {
	// valid owner and resource
	owner := "example@user"
	resource := "resource_id"
	expected := "example@user:resource_id:1"
	got, err := Format(owner, resource, true)
	require.NoError(t, err)
	require.Equal(t, expected, got)
	// malformed owner (doesn't allow : separator)
	owner = "example:user"
	resource = "resource_id"
	_, err = Format(owner, resource, false)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMalformed)
	// empty field (resource)
	owner = "example"
	resource = ""
	_, err = Format(owner, resource, false)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEmptyField)
}
