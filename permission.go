package authority

// Permission represents the database model of permissions
type Permission struct {
	ID   uint
	Name string
}

// TableName sets the table name
func (p Permission) TableName() string {
	return tablePrefix + "permissions"
}
