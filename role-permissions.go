package authority

type RolePermission struct {
	ID           uint
	RoleID       uint
	PermissionID uint
}

func (r RolePermission) TableName() string {
	return tablePrefix + "role_permissions"
}
