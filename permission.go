package authority

type Permission struct {
	ID   uint
	Name string
}

func (p Permission) TableName() string {
	return tablePrefix + "permissions"
}
