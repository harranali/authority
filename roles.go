package authority

// The database model of a role
type Role struct {
	ID   uint   // The role id (it gets set automatically by the database)
	Name string // The name of the role
	Slug string // String based unique identifier of the role, (use hyphen seperated role name '-', instead of space)
}

// TableName sets the table name
func (r Role) TableName() string {
	return auth.TablesPrefix + "roles"
}
