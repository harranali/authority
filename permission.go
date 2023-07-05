package authority

// Permission represents the database model of permissions
type Permission struct {
	ID   uint   // The permission id (it gets set automatically by the database)
	Name string // The permission name
	Slug string // String based unique identifier of the permission, (use hyphen seperated permission name '-', instead of space)
}

// TableName sets the table name
func (p Permission) TableName() string {
	return auth.TablesPrefix + "permissions"
}
