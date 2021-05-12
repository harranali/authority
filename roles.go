package authority

// Role represents the database model of roles
type Role struct {
	ID   uint
	Name string
}

// TableName sets the table name
func (r Role) TableName() string {
	return tablePrefix + "roles"
}
