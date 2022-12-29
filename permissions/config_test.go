package permissions

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

func Test_NewConfigFromData(t *testing.T) {
	t.Parallel()

	one := 1
	allow := policyDefaultAllow
	disallow := policyDefaultDisallow
	//nolint
	tests := []struct {
		err      error
		name     string
		filename string
		config   *config
	}{
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
			config: &config{
				Version: &one,
				Default: &allow,
			},
		},
		{
			name:     "disallow default",
			filename: "./testdata/disallow-default.yml",
			config: &config{
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
			config: &config{
				Version: &one,
				Default: &allow,
			},
		},
		{
			name:     "none perms",
			filename: "./testdata/none-perms.yml",
			config: &config{
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
			config: &config{
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
			config: &config{
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
			config: &config{
				Version: &one,
				Default: &allow,
				Permissions: &perms{
					ambientAuthority: permsByResType{
						ResourceTypeEnv: permNone,
						ResourceTypeFs:  permNone,
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
			config: &config{
				Version: &one,
				Default: &allow,
				Permissions: &perms{
					ambientAuthority: permsByResType{
						ResourceTypeEnv: permNone,
						ResourceTypeFs: p{
							ContextPermissions: &perm{
								"/another/file":   AccessRead,
								"/some/pattern/*": AccessRead | AccessExec,
								"/some/file":      AccessRead | AccessWrite,
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
			config: &config{
				Version: &one,
				Default: &allow,
				Permissions: &perms{
					ambientAuthority: permsByResType{
						ResourceTypeFs: permNone,
						ResourceTypeEnv: p{
							ContextPermissions: &perm{
								"ENV_NAME1": AccessRead | AccessWrite,
								"ENV_NAME2": AccessRead,
								"ENV_NAME3": AccessRead | AccessExec,
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
			data, err := os.ReadFile(tt.filename)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			p, err := NewConfigFromData(data)

			if err != nil || tt.err != nil {
				if !errCmp(err, tt.err) {
					t.Fatalf("unexpected error: %v", cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
				}
				return
			}

			if diff := cmp.Diff(*tt.config, *p); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TODO: test allowed functions.
