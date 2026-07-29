package permissions

import "testing"

func TestRoleValidation(t *testing.T) {
	tests := []struct {
		name    string
		role    Role
		wantErr bool
	}{
		{
			name:    "valid empty scope",
			role:    Role{ID: "role.user", Name: "User"},
			wantErr: false,
		},
		{
			name:    "valid system scope",
			role:    Role{ID: "builtin.admin", Name: "Admin", Scope: RoleScopeSystem, Tags: []string{"system", "admin"}},
			wantErr: false,
		},
		{
			name:    "valid team scope",
			role:    Role{ID: "role.team-lead", Name: "Team Lead", Scope: RoleScopeTeam, Tags: []string{"team"}},
			wantErr: false,
		},
		{
			name:    "valid object scope",
			role:    Role{ID: "role.doc-editor", Name: "Doc Editor", Scope: RoleScopeObject},
			wantErr: false,
		},
		{
			name:    "missing role ID",
			role:    Role{ID: "", Name: "No ID"},
			wantErr: true,
		},
		{
			name:    "invalid role scope",
			role:    Role{ID: "role.invalid", Name: "Invalid", Scope: "unknown_scope"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.role.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Role.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
