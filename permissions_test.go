package main

import (
	"errors"
	"os"
	"testing"

	//"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func errCmp(e1, e2 error) bool {
	return errors.Is(e1, e2) || errors.Is(e2, e1)
}

func Test_NewPermissionsFromFile(t *testing.T) {
	t.Parallel()

	one := 1
	allow := policyDefaultAllow
	disallow := policyDefaultDisallow
	//nolint
	tests := []struct {
		err         error
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
				Version: &one,
				Default: &allow,
			},
		},
		{
			name:     "disallow default",
			filename: "./testdata/disallow-default.yml",
			permissions: &permissionsPolicy{
				Version: &one,
				Default: &disallow,
			},
		},
		{
			name:     "invalid int perms",
			filename: "./testdata/invalid-int-perms.yml",
			err:      errInvalidPermissions,
		},
		{
			name:     "invalid str perms",
			filename: "./testdata/invalid-str-perms.yml",
			err:      errInvalidPermissions,
		},
		{
			name:     "no perms",
			filename: "./testdata/no-perms.yml",
			permissions: &permissionsPolicy{
				Version: &one,
				Default: &allow,
			},
		},
		{
			name:     "none perms",
			filename: "./testdata/none-perms.yml",
			permissions: &permissionsPolicy{
				Version: &one,
				Default: &allow,
				Permissions: &perms{
					ambientAuthority: permsByResType{},
				},
			},
		},
		{
			name:     "empty perms",
			filename: "./testdata/empty-perms.yml",
			permissions: &permissionsPolicy{
				Version: &one,
				Default: &allow,
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
			err:      errInvalidPermissions,
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
				Version: &one,
				Default: &allow,
				Permissions: &perms{
					ambientAuthority:              permsByResType{},
					"github.com/google/go-github": permsByResType{},
				},
			},
		},
		{
			name:     "perms fs none",
			filename: "./testdata/perms-fs-none.yml",
			permissions: &permissionsPolicy{
				Version: &one,
				Default: &allow,
				Permissions: &perms{
					ambientAuthority: permsByResType{
						resourceTypeEnv: permNone,
						resourceTypeFs:  permNone,
					},
					"github.com/google/go-github": permsByResType{},
				},
			},
		},
		{
			name:     "perms fs invalid str",
			filename: "./testdata/perms-fs-invalid-str.yml",
			err:      errInvalidPermissions,
		},
		{
			name:     "perms fs invalid int",
			filename: "./testdata/perms-fs-invalid-int.yml",
			err:      errInvalidPermissions,
		},
		{
			name:     "perms fs empty",
			filename: "./testdata/perms-fs-empty.yml",
			err:      errInvalidPermissions,
		},
		{
			name:     "perms fs file invalid def",
			filename: "./testdata/perms-fs-file-invalid-def.yml",
			err:      errInvalidPermissions,
		},
		{
			name:     "perms fs file invalid access",
			filename: "./testdata/perms-fs-file-invalid-access.yml",
			err:      errInvalidPermissions,
		},
		{
			name:     "perms fs file",
			filename: "./testdata/perms-fs-file.yml",
			permissions: &permissionsPolicy{
				Version: &one,
				Default: &allow,
				Permissions: &perms{
					ambientAuthority: permsByResType{
						resourceTypeEnv: permNone,
						resourceTypeFs: p{
							ContextPermissions: &perm{
								"/another/file":   accessRead,
								"/some/pattern/*": accessRead | accessExec,
								"/some/file":      accessRead | accessWrite,
							},
						},
					},
					"github.com/google/go-github": permsByResType{},
				},
			},
		},
		{
			name:     "perms env names",
			filename: "./testdata/perms-env-names.yml",
			permissions: &permissionsPolicy{
				Version: &one,
				Default: &allow,
				Permissions: &perms{
					ambientAuthority: permsByResType{
						resourceTypeFs: permNone,
						resourceTypeEnv: p{
							ContextPermissions: &perm{
								"ENV_NAME1": accessRead | accessWrite,
								"ENV_NAME2": accessRead,
								"ENV_NAME3": accessRead | accessExec,
							},
						},
					},
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

			if err != nil || tt.err != nil {
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
