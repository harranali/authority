package authority

type UserRole struct {
	ID     uint
	UserID uint
	RoleID uint
}

func (u UserRole) TableName() string {
	return tablePrefix + "user_roles"
}
