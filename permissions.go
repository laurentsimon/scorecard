package main

import (
	"errors"
	"fmt"
	"os"

	//"os"

	"gopkg.in/yaml.v3"
)

type access int

const (
	accessWrite access = 1
	accessRead  access = 2
	accessExec  access = 4
	accessNone  access = 0
)

type resourceType int

const (
	resourceTypeEnv resourceType = iota
	resourceTypeFs
	resourceTypeNet
	// resourceTypeRpc
	resourceTypeProcess
)

const (
	policyDefaultAllow policy = iota
	policyDefaultDisallow
)

const (
	permissionAllowed permission = iota
	permissionDisallowed
	permissionNotDefined
)

type (
	policy       int
	permission   int
	resourceName string
	// TODO: rename to be self-explanatory.
	perm map[resourceName]access
	p    struct {
		dangerousPermissions *perm
		contextPermissions   *perm
	}
	dependencyName  string
	perms           map[dependencyName]permsByResType
	permsByResType  map[resourceType]p
	filePermissions struct {
		Version     *int        `yaml:"version,omitempty"`
		Default     *string     `yaml:"default,omitempty"`
		Permissions interface{} `yaml:"permissions"`
	}
	permissionsPolicy struct {
		Version     int
		Default     policy
		Permissions perms
	}
)

var (
	errInvalidVersion     = errors.New("invalid version")
	errInvalidDefault     = errors.New("invalid default policy")
	errInvalidPermissions = errors.New("invalid permissions")
)

func NewPermissionsFromFile(file string) (*permissionsPolicy, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	fp, err := parseFromJSON(data)
	if err != nil {
		return nil, err
	}

	sp, err := fileToPolicy(fp)
	if err != nil {
		return nil, err
	}

	return sp, nil
}

func fileToPolicy(fp *filePermissions) (*permissionsPolicy, error) {
	p := permissionsPolicy{}
	if err := validateAndSetVersion(fp.Version, &p); err != nil {
		return nil, err
	}

	if err := validateAndSetDefault(fp.Default, &p); err != nil {
		return nil, err
	}

	if err := validateAndSetPermissions(fp.Permissions, &p); err != nil {
		return nil, err
	}

	return &p, nil
}

func validateAndSetPermissions(permissions interface{}, p *permissionsPolicy) error {
	switch v := permissions.(type) {
	case nil:
		return nil
	case string:
		return validateAndSetPermissionsFromString(v, p)
	case map[string]interface{}:
		return validateAndSetPermissionsFromMap(v, p)
	default:
		return fmt.Errorf("%w: type %q", errInvalidPermissions, v)
	}
	return nil
}

func validateAndSetPermissionsFromMap(value map[string]interface{}, p *permissionsPolicy) error {
	for k, v := range value {
		if k == "ambient" {
			k = "<local>"
		}
		switch vv := v.(type) {
		case string:
			if err := validateAndSetPermissionsFromMapString(dependencyName(k), vv, p); err != nil {
				return err
			}
			// TODO: other type.
		default:
			return fmt.Errorf("%w: type %q", errInvalidPermissions, vv)
		}
	}

	return nil
}

func validateAndSetPermissionsFromMapString(key dependencyName, value string, p *permissionsPolicy) error {
	if value != "none" &&
		value != "" {
		return fmt.Errorf("%w: %q", errInvalidPermissions, value)
	}

	if _, ok := p.Permissions[key]; ok {
		return fmt.Errorf("%w: duplicate entry: %q", errInvalidPermissions, value)
	}

	if p.Permissions == nil {
		p.Permissions = make(perms)
	}
	p.Permissions[key] = make(permsByResType)

	return nil
}

func validateAndSetPermissionsFromString(value string, p *permissionsPolicy) error {
	if value == "" ||
		value == "none" {
		return nil
	}

	return fmt.Errorf("%w: %q", errInvalidPermissions, value)
}

func validateAndSetDefault(def *string, p *permissionsPolicy) error {
	if def == nil {
		return fmt.Errorf("%w: no default policy found", errInvalidDefault)
	}
	switch *def {
	case "allow":
		p.Default = policyDefaultAllow
	case "disallow":
		p.Default = policyDefaultDisallow
	default:
		return fmt.Errorf("%w: %q", errInvalidDefault, *def)
	}
	return nil
}

func validateAndSetVersion(version *int, p *permissionsPolicy) error {
	if version == nil {
		return fmt.Errorf("%w: no version found", errInvalidVersion)
	}
	if *version != 1 {
		return fmt.Errorf("%w: %q", errInvalidVersion, *version)
	}
	p.Version = *version
	return nil
}

func parseFromJSON(content []byte) (*filePermissions, error) {
	fp := filePermissions{}

	err := yaml.Unmarshal(content, &fp)
	if err != nil {
		return nil, fmt.Errorf("%w: yaml.Unmarshal()", err)
	}
	return &fp, nil
}
