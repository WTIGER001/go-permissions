package permissions

import "strings"

type CRUDAction string

const (
	PermissionSuffixCreate = "create"
	PermissionSuffixRead   = "read"
	PermissionSuffixUpdate = "update"
	PermissionSuffixDelete = "delete"
	PermissionSuffixGrant  = "grant"
)

const (
	CRUDCreate CRUDAction = PermissionSuffixCreate
	CRUDRead   CRUDAction = PermissionSuffixRead
	CRUDUpdate CRUDAction = PermissionSuffixUpdate
	CRUDDelete CRUDAction = PermissionSuffixDelete
	CRUDGrant  CRUDAction = PermissionSuffixGrant
)

type CRUDPermissionOptions struct {
	Namespace          string
	ResourceName       string
	NameBuilder        func(action CRUDAction, resourceName string) string
	DescriptionBuilder func(action CRUDAction, resourceName string) string
}

type SystemCRUDPermissions struct {
	Create *SystemPermission
	Read   *SystemPermission
	Update *SystemPermission
	Delete *SystemPermission
	Grant  *SystemPermission
}

type TeamCRUDPermissions struct {
	Create *TeamPermission
	Read   *TeamPermission
	Update *TeamPermission
	Delete *TeamPermission
	Grant  *TeamPermission
}

func NewSystemCRUDPermissions(rootPermissionID string) SystemCRUDPermissions {
	return NewSystemCRUDPermissionsWithOptions(rootPermissionID, CRUDPermissionOptions{})
}

func NewSystemCRUDPermissionsWithOptions(rootPermissionID string, options CRUDPermissionOptions) SystemCRUDPermissions {
	parts := buildCRUDParts(rootPermissionID, options)

	return SystemCRUDPermissions{
		Create: NewSystemPermission(parts.rootID+".create", parts.namespace, parts.nameBuilder(CRUDCreate, parts.resourceName), parts.descriptionBuilder(CRUDCreate, parts.resourceName)),
		Read:   NewSystemPermission(parts.rootID+".read", parts.namespace, parts.nameBuilder(CRUDRead, parts.resourceName), parts.descriptionBuilder(CRUDRead, parts.resourceName)),
		Update: NewSystemPermission(parts.rootID+".update", parts.namespace, parts.nameBuilder(CRUDUpdate, parts.resourceName), parts.descriptionBuilder(CRUDUpdate, parts.resourceName)),
		Delete: NewSystemPermission(parts.rootID+".delete", parts.namespace, parts.nameBuilder(CRUDDelete, parts.resourceName), parts.descriptionBuilder(CRUDDelete, parts.resourceName)),
		Grant:  NewSystemPermission(parts.rootID+".grant", parts.namespace, parts.nameBuilder(CRUDGrant, parts.resourceName), parts.descriptionBuilder(CRUDGrant, parts.resourceName)),
	}
}

func NewTeamCRUDPermissions(rootPermissionID string) TeamCRUDPermissions {
	return NewTeamCRUDPermissionsWithOptions(rootPermissionID, CRUDPermissionOptions{})
}

func NewTeamCRUDPermissionsWithOptions(rootPermissionID string, options CRUDPermissionOptions) TeamCRUDPermissions {
	parts := buildCRUDParts(rootPermissionID, options)

	return TeamCRUDPermissions{
		Create: NewTeamPermission(parts.rootID+".create", parts.namespace, parts.nameBuilder(CRUDCreate, parts.resourceName), parts.descriptionBuilder(CRUDCreate, parts.resourceName)),
		Read:   NewTeamPermission(parts.rootID+".read", parts.namespace, parts.nameBuilder(CRUDRead, parts.resourceName), parts.descriptionBuilder(CRUDRead, parts.resourceName)),
		Update: NewTeamPermission(parts.rootID+".update", parts.namespace, parts.nameBuilder(CRUDUpdate, parts.resourceName), parts.descriptionBuilder(CRUDUpdate, parts.resourceName)),
		Delete: NewTeamPermission(parts.rootID+".delete", parts.namespace, parts.nameBuilder(CRUDDelete, parts.resourceName), parts.descriptionBuilder(CRUDDelete, parts.resourceName)),
		Grant:  NewTeamPermission(parts.rootID+".grant", parts.namespace, parts.nameBuilder(CRUDGrant, parts.resourceName), parts.descriptionBuilder(CRUDGrant, parts.resourceName)),
	}
}

type crudParts struct {
	rootID             string
	namespace          string
	resourceName       string
	nameBuilder        func(action CRUDAction, resourceName string) string
	descriptionBuilder func(action CRUDAction, resourceName string) string
}

func buildCRUDParts(rootPermissionID string, options CRUDPermissionOptions) crudParts {
	rootID, derivedNamespace, derivedResourceName, _ := crudPermissionParts(rootPermissionID)

	namespace := strings.TrimSpace(options.Namespace)
	if namespace == "" {
		namespace = derivedNamespace
	}

	resourceName := strings.TrimSpace(options.ResourceName)
	if resourceName == "" {
		resourceName = derivedResourceName
	}

	nameBuilder := options.NameBuilder
	if nameBuilder == nil {
		nameBuilder = defaultCRUDNameBuilder
	}

	descriptionBuilder := options.DescriptionBuilder
	if descriptionBuilder == nil {
		descriptionBuilder = defaultCRUDDescriptionBuilder
	}

	return crudParts{
		rootID:             rootID,
		namespace:          namespace,
		resourceName:       resourceName,
		nameBuilder:        nameBuilder,
		descriptionBuilder: descriptionBuilder,
	}
}

func defaultCRUDNameBuilder(action CRUDAction, resourceName string) string {
	return humanizePermissionToken(string(action)) + " " + resourceName
}

func defaultCRUDDescriptionBuilder(action CRUDAction, resourceName string) string {
	resourceNameLower := strings.ToLower(resourceName)
	verb := "using"
	switch action {
	case CRUDCreate:
		verb = "creating"
	case CRUDRead:
		verb = "reading"
	case CRUDUpdate:
		verb = "updating"
	case CRUDDelete:
		verb = "deleting"
	case CRUDGrant:
		verb = "granting"
	}

	return "Allows " + verb + " " + resourceNameLower + "."
}

func crudPermissionParts(rootPermissionID string) (rootID, namespace, resourceName, resourceNameLower string) {
	normalizedRoot := strings.Trim(rootPermissionID, " .")
	if normalizedRoot == "" {
		normalizedRoot = "resource"
	}

	segments := strings.Split(normalizedRoot, ".")
	namespace = humanizePermissionToken(segments[0])
	resourceName = humanizePermissionToken(strings.Join(segments, " "))
	resourceNameLower = strings.ToLower(resourceName)

	return normalizedRoot, namespace, resourceName, resourceNameLower
}

func humanizePermissionToken(value string) string {
	if value == "" {
		return "Resource"
	}

	replacer := strings.NewReplacer(".", " ", "_", " ", "-", " ", "/", " ")
	words := strings.Fields(replacer.Replace(value))
	if len(words) == 0 {
		return "Resource"
	}

	for i := range words {
		if words[i] == "" {
			continue
		}
		first := strings.ToUpper(words[i][:1])
		rest := ""
		if len(words[i]) > 1 {
			rest = strings.ToLower(words[i][1:])
		}
		words[i] = first + rest
	}

	return strings.Join(words, " ")
}
