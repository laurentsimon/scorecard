package main

import (
	"errors"
	//"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func errCmp(e1, e2 error) bool {
	return errors.Is(e1, e2) || errors.Is(e2, e1)
}

func Test_NewPermissionsFromFile(t *testing.T) {
	t.Parallel()

	//nolint
	tests := []struct {
		err         error
		errText     string
		name        string
		filename    string
		permissions *permissionsPolicy
	}{
		{
			name:     "non existent file",
			filename: "./testdata/some-file.yml",
			err:      os.ErrNotExist,
		},
		{
			name:     "no version",
			filename: "./testdata/no-version.yml",
			err:      errInvalidVersion,
		},
		{
			name:     "invalid version",
			filename: "./testdata/invalid-version.yml",
			err:      errInvalidVersion,
		},
		{
			name:     "no default",
			filename: "./testdata/no-default.yml",
			err:      errInvalidDefault,
		},
		{
			name:     "invalid default",
			filename: "./testdata/invalid-default.yml",
			err:      errInvalidDefault,
		},
		{
			name:     "allow default",
			filename: "./testdata/allow-default.yml",
			permissions: &permissionsPolicy{
				Version: 1,
				Default: policyDefaultAllow,
			},
		},
		{
			name:     "disallow default",
			filename: "./testdata/disallow-default.yml",
			permissions: &permissionsPolicy{
				Version: 1,
				Default: policyDefaultDisallow,
			},
		},
		{
			name:     "invalid int perms",
			filename: "./testdata/invalid-int-perms.yml",
			err:      errInvalidPermissions,
		},
		{
			name:     "no perms",
			filename: "./testdata/no-perms.yml",
			permissions: &permissionsPolicy{
				Version: 1,
				Default: policyDefaultAllow,
			},
		},
		{
			name:     "none perms",
			filename: "./testdata/none-perms.yml",
			permissions: &permissionsPolicy{
				Version: 1,
				Default: policyDefaultAllow,
			},
		},
		{
			name:     "empty perms",
			filename: "./testdata/empty-perms.yml",
			permissions: &permissionsPolicy{
				Version: 1,
				Default: policyDefaultAllow,
			},
		},
		{
			name:     "invalid string perms",
			filename: "./testdata/perms-invalid-string.yml",
			err:      errInvalidPermissions,
		},
		{
			name:     "duplicate none perms",
			filename: "./testdata/duplicate-none-perms.yml",
			errText:  "already defined at line",
		},
		{
			name:     "perms multiple invalid string",
			filename: "./testdata/perms-multiple-invalid-string.yml",
			err:      errInvalidPermissions,
		},
		{
			name:     "perms none",
			filename: "./testdata/perms-none.yml",
			permissions: &permissionsPolicy{
				Version: 1,
				Default: policyDefaultAllow,
				Permissions: perms{
					"<local>":                     permsByResType{},
					"github.com/google/go-github": permsByResType{},
				},
			},
		},
	}

	for i := range tests {
		tt := &tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p, err := NewPermissionsFromFile(tt.filename)

			if tt.errText != "" {
				// Duplicate entries trigger a parsing error but there is not particulat type
				// we can check. There is only text we can look at.
				if !strings.Contains(err.Error(), tt.errText) {
					t.Fatalf("unexpected error: %v", cmp.Diff(err.Error(), tt.errText))
				}
				return
			} else if err != nil || tt.err != nil {
				if !errCmp(err, tt.err) {
					t.Fatalf("unexpected error: %v", cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
				}
				return
			}

			if diff := cmp.Diff(*tt.permissions, *p); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TODO: test allowed functions.
