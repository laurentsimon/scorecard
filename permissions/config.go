package permissions

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type ResourceType int

const (
	ResourceTypeEnv ResourceType = iota
	ResourceTypeFs
	ResourceTypeNet
	// ResourceTypeRpc
	ResourceTypeProcess
)

const (
	policyDefaultDisallow policy = iota
	policyDefaultAllow
)

type (
	resourceName string
	perm         map[resourceName]Access
	Access       int
	permission   int
)

const (
	permissionAllowed permission = iota
	permissionDisallowed
	permissionNotDefined
)

const (
	AccessWrite Access = 1
	AccessRead  Access = 2
	AccessExec  Access = 4
	AccessNone  Access = 0
)

type (
	policy int
	p      struct {
		DangerousPermissions *perm
		ContextPermissions   *perm
	}
	dependencyName string
	perms          map[dependencyName]permsByResType
	permsByResType map[ResourceType]p
	config         struct {
		Version     *int    `yaml:"version"`
		Default     *policy `yaml:"default"`
		Permissions *perms  `yaml:"permissions"`
	}
)

var permNone = p{
	DangerousPermissions: &perm{
		"*": AccessNone,
	},
	ContextPermissions: &perm{
		"*": AccessNone,
	},
}

var permsNone = permsByResType{
	ResourceTypeEnv:     permNone,
	ResourceTypeFs:      permNone,
	ResourceTypeNet:     permNone,
	ResourceTypeProcess: permNone,
}

var ambientAuthority dependencyName = "<ambient>"

var (
	errInvalidVersion     = errors.New("invalid version")
	errInvalidDefault     = errors.New("invalid default policy")
	errInvalidPermissions = errors.New("invalid permissions")
)

func NewConfigFromData(data []byte) (*config, error) {
	c, err := parseFromJSON(data)
	if err != nil {
		return nil, err
	}

	if err := c.validate(); err != nil {
		return nil, err
	}

	return c, nil
}

func parseFromJSON(content []byte) (*config, error) {
	c := config{}

	err := yaml.Unmarshal(content, &c)
	if err != nil {
		return nil, fmt.Errorf("%w: yaml.Unmarshal()", err)
	}
	return &c, nil
}

func (c *config) validate() error {
	if err := c.validateVersion(); err != nil {
		return err
	}

	if err := c.validateDefault(); err != nil {
		return err
	}

	return nil
}

func (c *config) validateDefault() error {
	if c.Default == nil {
		return fmt.Errorf("%w: no default found", errInvalidDefault)
	}

	return nil
}

func (c *config) validateVersion() error {
	if c.Version == nil {
		return fmt.Errorf("%w: no version found", errInvalidVersion)
	}
	if *c.Version != 1 {
		return fmt.Errorf("%w: %q", errInvalidVersion, *c.Version)
	}
	return nil
}

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

func parseResourceType(name string) (*ResourceType, error) {
	var resType ResourceType
	switch name {
	case "fs":
		resType = ResourceTypeFs
	case "env":
		resType = ResourceTypeEnv
	case "net":
		resType = ResourceTypeNet
		// case "exec": resType = ResourceTypeExec
	default:
		return nil, fmt.Errorf("%w: resource type %q", errInvalidPermissions, name)
	}
	return &resType, nil
}

func parseResourcePermissions(key string, value interface{}) (*ResourceType, *p, error) {
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
			acc := AccessNone
			if strings.Contains(vv, "r") {
				acc |= AccessRead
			}
			if strings.Contains(vv, "w") {
				acc |= AccessWrite
			}
			if strings.Contains(vv, "x") {
				acc |= AccessExec
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
