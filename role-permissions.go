package authority

// RolePermission stores the relationship between roles and permissions
type RolePermission struct {
	ID           uint
	RoleID       uint
	PermissionID uint
}

// TableName sets the table name
func (r RolePermission) TableName() string {
	return tablePrefix + "role_permissions"
}
