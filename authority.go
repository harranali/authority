package authority

import (
	"errors"

	"gorm.io/gorm"
)

type Authority struct {
	DB *gorm.DB
}

type Options struct {
	TablesPrefix string
	DB           *gorm.DB
}

var tablePrefix string

var auth *Authority

func New(opts Options) *Authority {
	tablePrefix = opts.TablesPrefix
	auth = &Authority{
		DB: opts.DB,
	}

	migrateTabes(opts.DB)
	return auth
}

func Resolve() *Authority {
	return auth
}

func (a *Authority) CreateRole(role string) error {
	var dbRole Role
	res := a.DB.Where("name = ?", role).First(&dbRole)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			// create
			a.DB.Create(&Role{Name: role})
			return nil
		}
	}

	return res.Error
}

func (a *Authority) CreatePermissions(perm string) error {
	var dbPerm Permission
	res := a.DB.Where("name = ?", perm).First(&dbPerm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			// create
			a.DB.Create(&Permission{Name: perm})
			return nil
		}
	}

	return res.Error
}

func (a *Authority) AssignPermissions(roleName string, permNames []string) error {
	// get the role id
	var role Role
	rRes := a.DB.Where("name = ?", roleName).First(&role)
	if rRes.Error != nil {
		if errors.Is(rRes.Error, gorm.ErrRecordNotFound) {
			return errors.New("role record not found")
		}

		return rRes.Error
	}

	var perms []Permission
	// get the permissions ids
	for _, permName := range permNames {
		var perm Permission
		pRes := a.DB.Where("name = ?", permName).First(&perm)
		if pRes.Error != nil {
			if errors.Is(pRes.Error, gorm.ErrRecordNotFound) {
				return errors.New("a permission record not found")
			}

			return pRes.Error
		}

		perms = append(perms, perm)
	}

	// insert data into RolePermissions table
	for _, perm := range perms {
		// ignore any assigned permission
		var rolePerm RolePermission
		res := a.DB.Where("role_id = ?", role.ID).Where("permission_id =?", perm.ID).First(&rolePerm)
		if res.Error != nil {
			// assign the record
			cRes := a.DB.Create(&RolePermission{RoleID: role.ID, PermissionID: perm.ID})
			if cRes.Error != nil {
				return cRes.Error
			}
		}
	}

	return nil
}

func (a *Authority) AssignRole(userID uint, roleName string) error {
	// find the role
	var role Role
	res := a.DB.Where("name = ?", roleName).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return errors.New("missing role record")
		}
		return res.Error
	}

	var userRole UserRole
	res = a.DB.Where("user_id = ?", userID).Where("role_id = ?", role.ID).First(&userRole)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			// create
			cRes := a.DB.Create(&UserRole{UserID: userID, RoleID: role.ID})
			if cRes.Error != nil {
				return errors.New("error assigning user, " + cRes.Error.Error())
			}
			return nil
		}

		return res.Error
	}

	return errors.New("user have a role assgined")
}

func migrateTabes(db *gorm.DB) {
	db.AutoMigrate(&Role{})
	db.AutoMigrate(&Permission{})
	db.AutoMigrate(&RolePermission{})
	db.AutoMigrate(&UserRole{})
}
