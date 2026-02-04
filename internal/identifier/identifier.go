package identifier

import (
	"fmt"
	"slices"
	"strings"
)

const IDSep = ":"

var (
	ErrMalformed  = fmt.Errorf("identifier: malformed")
	ErrEmptyField = fmt.Errorf("identifier: empty field")
)

type Identifier struct {
	Owner    string
	Resource string
	Private  bool
}

func New(id string) (*Identifier, error) {
	split := strings.Split(id, IDSep)
	if len(split) != 3 {
		return nil, ErrMalformed
	}
	if slices.Contains(split, "") {
		return nil, ErrEmptyField
	}
	private, err := stringToBool(split[2])
	if err != nil {
		return nil, err
	}
	return &Identifier{
		Owner:    split[0],
		Resource: split[1],
		Private:  private,
	}, nil
}

func (i *Identifier) String() string {
	private := boolToString(i.Private)
	return strings.Join([]string{i.Owner, i.Resource, private}, IDSep)
}

func Format(owner string, resource string, private bool) (string, error) {
	if owner == "" || resource == "" {
		return "", ErrEmptyField
	}
	if strings.Contains(owner, IDSep) || strings.Contains(resource, IDSep) {
		return "", ErrMalformed
	}
	priv := boolToString(private)
	return strings.Join([]string{owner, resource, priv}, IDSep), nil
}
