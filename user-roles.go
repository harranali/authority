package authority

// The link between the users and roles
type UserRole struct {
	ID     uint   // Unique id (it gets set automatically by the database)
	UserID string // The user id
	RoleID uint   // The role id
}

// TableName sets the table name
func (u UserRole) TableName() string {
	return auth.TablesPrefix + "user_roles"
}
