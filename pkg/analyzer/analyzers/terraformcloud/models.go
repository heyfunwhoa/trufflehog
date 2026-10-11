package terraformcloud

const (
	resourceTypeAccount      = "Account"
	resourceTypeOrganization = "Organization"
	resourceTypeWorkspace    = "Workspace"
	resourceTypeVariableSet  = "VariableSet"

	permCanReadVariable    = "can-read-variable"
	permCanUpdateVariable  = "can-update-variable"
	permCanReadVarsets     = "can-read-varsets"
	permCanManageVarsets   = "can-manage-varsets"
	permCanCreateWorkspace = "can-create-workspace"
	permCanDestroy         = "can-destroy"
	permCanQueueRun        = "can-queue-run"
)

// SecretInfo is the collected analysis of a Terraform Cloud / HCP Terraform token.
type SecretInfo struct {
	Account       Account
	Organizations []Organization
}

// Account is the token's authenticated user (or synthetic service user for team/org tokens).
type Account struct {
	ID                        string
	Username                  string
	Email                     string
	IsServiceAccount          bool
	IsSiteAdmin               bool
	AuthenticatedResourceType string
	AuthenticatedResourceID   string
	Permissions               []string
}

// Organization is an organization the token can list, plus nested resources.
type Organization struct {
	ID          string
	Name        string
	Email       string
	Permissions []string
	Workspaces  []Workspace
	Varsets     []Varset
}

// Workspace is a workspace the token can list. Permissions come from the list API
// and include whether the token can read or update workspace variables.
type Workspace struct {
	ID               string
	Name             string
	ExecutionMode    string
	TerraformVersion string
	Locked           bool
	Permissions      []string
}

// Varset is a variable set the token can list. Names only — values are never fetched.
type Varset struct {
	ID          string
	Name        string
	Description string
	Global      bool
	Priority    bool
}

func (w Workspace) hasPermission(name string) bool {
	for _, perm := range w.Permissions {
		if perm == name {
			return true
		}
	}
	return false
}

func (o Organization) hasPermission(name string) bool {
	for _, perm := range o.Permissions {
		if perm == name {
			return true
		}
	}
	return false
}

func (s *SecretInfo) workspacesWithVariableRead() int {
	count := 0
	for _, org := range s.Organizations {
		for _, ws := range org.Workspaces {
			if ws.hasPermission(permCanReadVariable) {
				count++
			}
		}
	}
	return count
}
