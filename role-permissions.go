package authority

// The link between the roles and permissions
type RolePermission struct {
	ID           uint // Unique id (it gets set automatically by the database)
	RoleID       uint // Role id
	PermissionID uint // Permission id
}

// TableName sets the table name
func (r RolePermission) TableName() string {
	return auth.TablesPrefix + "role_permissions"
}
