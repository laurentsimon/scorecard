package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

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
	policyDefaultDisallow policy = iota
	policyDefaultAllow
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
		DangerousPermissions *perm
		ContextPermissions   *perm
	}
	dependencyName     string
	perms              map[dependencyName]permsByResType
	permsByResType     map[resourceType]p
	permissionsManager struct {
		Version     *int    `yaml:"version"`
		Default     *policy `yaml:"default"`
		Permissions *perms  `yaml:"permissions"`
	}
	// permissionsManager struct {
	// 	Version     int
	// 	Default     policy
	// 	Permissions perms
	// }
)

var permNone = p{
	DangerousPermissions: &perm{
		"*": accessNone,
	},
	ContextPermissions: &perm{
		"*": accessNone,
	},
}

var permsNone = permsByResType{
	resourceTypeEnv:     permNone,
	resourceTypeFs:      permNone,
	resourceTypeNet:     permNone,
	resourceTypeProcess: permNone,
}

var ambientAuthority dependencyName = "<ambient>"

var (
	errInvalidVersion     = errors.New("invalid version")
	errInvalidDefault     = errors.New("invalid default policy")
	errInvalidPermissions = errors.New("invalid permissions")
)

// https://abhinavg.net/2021/02/24/flexible-yaml/
func (p *policy) UnmarshalYAML(n *yaml.Node) error {
	var str string
	if err := n.Decode(&str); err != nil {
		return fmt.Errorf("%w: %v", errInvalidDefault, err)
	}

	switch n.Value {
	case "allow":
		*p = policyDefaultAllow
	case "disallow":
		*p = policyDefaultDisallow
	default:
		return fmt.Errorf("%w: %q", errInvalidDefault, str)
	}
	return nil
}

func (p *perms) UnmarshalYAML(n *yaml.Node) error {
	fmt.Println("value:", n.Value)
	// Handle string.
	var str string
	if err := n.Decode(&str); err == nil {
		// This is a string. It MUST be `none`.
		if str != "none" {
			return fmt.Errorf("%w: %q", errInvalidPermissions, str)
		}
		// None permissions for the ambient authority.
		*p = perms{
			ambientAuthority: permsByResType{},
		}
		return nil
	}

	// Handle map to string.
	var mss map[string]string
	if err := n.Decode(&mss); err == nil {
		*p = make(perms)
		for k, v := range mss {
			if v != "none" {
				return fmt.Errorf("%w: %q", errInvalidPermissions, v)
			}

			(*p)[dependencyName(k)] = make(permsByResType)
		}
		return nil
	}

	// Handle map to structure.
	var msst map[string]interface{}
	if err := n.Decode(&msst); err == nil {
		*p = make(perms)
		for k, v := range msst {
			if _, ok := (*p)[dependencyName(k)]; ok {
				return fmt.Errorf("%w: duplicate entry: %q", errInvalidPermissions, k)
			}
			switch vv := v.(type) {
			case string:
				if vv != "none" {
					return fmt.Errorf("%w: %q", errInvalidPermissions, vv)
				}
				(*p)[dependencyName(k)] = permsByResType{}
				continue

			case map[string]interface{}:
				(*p)[dependencyName(k)] = permsByResType{}
				for kp, vp := range vv {
					// TODO: duplicate
					t, resp, err := parseResourcePermissions(kp, vp)
					if err != nil {
						return err
					}
					// TODO: remove
					if t != nil && resp != nil {
						(*p)[dependencyName(k)][*t] = *resp
					}

				}
			default:
				return fmt.Errorf("%w: type %v", errInvalidPermissions, vv)
			}
		}
		return nil
	}

	return fmt.Errorf("%w: %q", errInvalidPermissions, n.Value)
}

func parseResourceType(name string) (*resourceType, error) {
	var resType resourceType
	switch name {
	case "fs":
		resType = resourceTypeFs
	case "env":
		resType = resourceTypeEnv
	case "net":
		resType = resourceTypeNet
		// case "exec": resType = resourceTypeExec
	default:
		return nil, fmt.Errorf("%w: resource type %q", errInvalidPermissions, name)
	}
	return &resType, nil
}

func parseResourcePermissions(key string, value interface{}) (*resourceType, *p, error) {
	resType, err := parseResourceType(key)
	if err != nil {
		return nil, nil, err
	}

	// Parse the permission.
	switch v := value.(type) {
	case nil:
		return nil, nil, fmt.Errorf("%w: empty %v", errInvalidPermissions, key)
	case string:
		if v != "none" {
			return nil, nil, fmt.Errorf("%w: %q", errInvalidPermissions, v)
		}
		return resType, &permNone, nil
	case map[string]interface{}:
		p, err := parsePermissionDefinition(v)
		if err != nil {
			return nil, nil, err
		}
		return resType, p, nil

	default:
		return nil, nil, fmt.Errorf("%w: resource %v: %v of type %T", errInvalidPermissions, key, v, v)
	}

	fmt.Println(resType, value)
	return nil, nil, nil
}

func parsePermissionDefinition(permsDef map[string]interface{}) (*p, error) {
	result := p{}
	for k, v := range permsDef {
		switch vv := v.(type) {
		case string:
			for _, c := range vv {
				if c != 'r' && c != 'w' && c != 'x' {
					return nil, fmt.Errorf("%w: %q", errInvalidPermissions, vv)
				}
			}
			acc := accessNone
			if strings.Contains(vv, "r") {
				acc |= accessRead
			}
			if strings.Contains(vv, "w") {
				acc |= accessWrite
			}
			if strings.Contains(vv, "x") {
				acc |= accessExec
			}

			if result.ContextPermissions == nil {
				result.ContextPermissions = &perm{}
			}
			(*result.ContextPermissions)[resourceName(k)] = acc
		default:
			return nil, fmt.Errorf("%w: %v of type %T", errInvalidPermissions, vv, vv)
		}
	}
	return &result, nil
}

func NewPermissionsFromFile(file string) (*permissionsManager, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return NewPermissionsFromData(data)
}

func NewPermissionsFromData(data []byte) (*permissionsManager, error) {
	sp, err := parseFromJSON(data)
	if err != nil {
		return nil, err
	}

	if err := validate(sp); err != nil {
		return nil, err
	}

	return sp, nil
}

func validate(pp *permissionsManager) error {
	if err := pp.validateVersion(); err != nil {
		return err
	}

	if err := pp.validateDefault(); err != nil {
		return err
	}

	return nil
}

func parseFromJSON(content []byte) (*permissionsManager, error) {
	sp := permissionsManager{}

	err := yaml.Unmarshal(content, &sp)
	if err != nil {
		return nil, fmt.Errorf("%w: yaml.Unmarshal()", err)
	}
	return &sp, nil
}

func (pp *permissionsManager) validateDefault() error {
	if pp.Default == nil {
		return fmt.Errorf("%w: no default found", errInvalidDefault)
	}

	return nil
}

func (pp *permissionsManager) validateVersion() error {
	if pp.Version == nil {
		return fmt.Errorf("%w: no version found", errInvalidVersion)
	}
	if *pp.Version != 1 {
		return fmt.Errorf("%w: %q", errInvalidVersion, *pp.Version)
	}
	return nil
}
