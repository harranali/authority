package authority

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// Authority helps deal with permissions
type Authority struct {
	TablesPrefix string
	DB           *gorm.DB
}

// Options has the options for initiating the package
type Options struct {
	TablesPrefix string
	DB           *gorm.DB
}

var (
	ErrPermissionInUse    = errors.New("cannot delete assigned permission")
	ErrPermissionNotFound = errors.New("permission not found")
	ErrRoleInUse          = errors.New("cannot delete assigned role")
	ErrRoleNotFound       = errors.New("role not found")
)

var tablePrefix string

var auth *Authority
var options Options
var tx *gorm.DB

// New initiates authority
func New(opts Options) *Authority {
	options = opts
	auth = &Authority{
		TablesPrefix: options.TablesPrefix,
		DB:           opts.DB,
	}

	migrateTables(opts.DB)
	return auth
}

// New initiates new instance of authority
func newInstance(opts Options) *Authority {
	newAuth := &Authority{
		DB: opts.DB,
	}

	migrateTables(opts.DB)
	return newAuth
}

// Resolve returns the initiated instance
func Resolve() *Authority {
	return auth
}

// Add a new role to the database
// it accepts the Role struct as a parameter
// it returns an error in case of any
// it returns an error if the role is already exists
func (a *Authority) CreateRole(r Role) error {
	roleSlug := r.Slug
	var dbRole Role
	res := a.DB.Where("slug = ?", roleSlug).First(&dbRole)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			// create
			createRes := a.DB.Create(&r)
			if createRes.Error != nil {
				return createRes.Error
			}
			return nil
		}
		return res.Error
	}

	return errors.New(fmt.Sprintf("role '%v' already exists", roleSlug))
}

// Add a new permission to the database
// it accepts the Permission struct as a parameter
// it returns an error in case of any
// it returns an error if the permission is already exists
func (a *Authority) CreatePermission(p Permission) error {
	permSlug := p.Slug
	var dbPerm Permission
	res := a.DB.Where("slug = ?", permSlug).First(&dbPerm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			// create
			createRes := a.DB.Create(&p)
			if createRes.Error != nil {
				return createRes.Error
			}
			return nil
		}
		return res.Error
	}

	return errors.New(fmt.Sprintf("permission '%v' already exists", permSlug))
}

// Assigns a group of permissions to a given role
// it accepts the the role slug as the first parameter
// the second parameter is a slice of permission slugs (strings) to be assigned to the role
// it returns an error in case of any
// it returns an error in case the role does not exists
// it returns an error in case any of the permissions does not exists
// it returns an error in case any of the permissions is already assigned
func (a *Authority) AssignPermissionsToRole(roleSlug string, permSlugs []string) error {
	var role Role
	rRes := a.DB.Where("slug = ?", roleSlug).First(&role)
	if rRes.Error != nil {
		if errors.Is(rRes.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}
		return rRes.Error
	}
	var perms []Permission
	for _, permSlug := range permSlugs {
		var perm Permission
		pRes := a.DB.Where("slug = ?", permSlug).First(&perm)
		if pRes.Error != nil {
			if errors.Is(pRes.Error, gorm.ErrRecordNotFound) {
				return ErrPermissionNotFound
			}
			return pRes.Error
		}
		perms = append(perms, perm)
	}
	tx := a.DB.Begin()
	for _, perm := range perms {
		var rolePerm RolePermission
		res := a.DB.Where("role_id = ?", role.ID).Where("permission_id =?", perm.ID).First(&rolePerm)
		if res.Error != nil && errors.Is(res.Error, gorm.ErrRecordNotFound) {
			cRes := tx.Create(&RolePermission{RoleID: role.ID, PermissionID: perm.ID})
			if cRes.Error != nil {
				tx.Rollback()
				return cRes.Error
			}
		}
		if res.Error != nil && !errors.Is(res.Error, gorm.ErrRecordNotFound) {
			tx.Rollback()
			return res.Error
		}
		if rolePerm != (RolePermission{}) {
			tx.Rollback()
			return errors.New(fmt.Sprintf("permission '%v' is aleady assigned to the role '%v'", perm.Name, role.Name))
		}
		rolePerm = RolePermission{}
	}
	return tx.Commit().Error
}

// Assigns a role to a given user
// it accepts the user id as the first parameter
// the second parameter the role slug
// it returns an error in case of any
// it returns an error in case the role does not exists
// it returns an error in case the role is already assigned
func (a *Authority) AssignRoleToUser(userID uint, roleSlug string) error {
	var role Role
	res := a.DB.Where("slug = ?", roleSlug).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}
		return res.Error
	}
	var userRole UserRole
	res = a.DB.Where("user_id = ?", userID).Where("role_id = ?", role.ID).First(&userRole)
	if res.Error != nil && errors.Is(res.Error, gorm.ErrRecordNotFound) {
		a.DB.Create(&UserRole{UserID: userID, RoleID: role.ID})
		return nil
	}
	if res.Error != nil && !errors.Is(res.Error, gorm.ErrRecordNotFound) {
		return res.Error
	}

	return errors.New(fmt.Sprintf("this role '%v' is already assigned to the user", roleSlug))
}

// Checks if a role is assigned to a user
// it accepts the user id as the first parameter
// the second parameter the role slug
// it returns two parameters
// the first parameter of the return is a boolean represents whether the role is assigned or not
// the second is an error in case of any
// in case the role does not exists, an error is returned
func (a *Authority) CheckUserRole(userID interface{}, roleSlug string) (bool, error) {
	userIDStr := fmt.Sprintf("%v", userID)
	// find the role
	var role Role
	res := a.DB.Where("slug = ?", roleSlug).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, ErrRoleNotFound
		}
		return false, res.Error
	}

	// check if the role is a assigned
	var userRole UserRole
	res = a.DB.Where("user_id = ?", userIDStr).Where("role_id = ?", role.ID).First(&userRole)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, res.Error
	}

	return true, nil
}

// Checks if a permission is assigned to a user
// it accepts in the user id as the first parameter
// the second parameter the role slug
// it returns two parameters
// the first parameter of the return is a boolean represents whether the role is assigned or not
// the second is an error in case of any
// in case the role does not exists, an error is returned
func (a *Authority) CheckUserPermission(userID interface{}, permSlug string) (bool, error) {
	userIDStr := fmt.Sprintf("%v", userID)
	// the user role
	var userRoles []UserRole
	res := a.DB.Where("user_id = ?", userIDStr).Find(&userRoles)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, res.Error
	}

	//prepare an array of role ids
	var roleIDs []interface{}
	for _, r := range userRoles {
		roleIDs = append(roleIDs, r.RoleID)
	}

	// find the permission
	var perm Permission
	res = a.DB.Where("slug = ?", permSlug).First(&perm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, ErrPermissionNotFound
		}
		return false, res.Error
	}

	// find the role permission
	var rolePermission RolePermission
	res = a.DB.Where("role_id IN (?)", roleIDs).Where("permission_id = ?", perm.ID).First(&rolePermission)
	if res.Error != nil && errors.Is(res.Error, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if res.Error != nil && !errors.Is(res.Error, gorm.ErrRecordNotFound) {
		return false, res.Error
	}

	return true, nil
}

// Checks if a permission is assigned to a role
// it accepts in the role slug as the first parameter
// the second parameter the permission slug
// it returns two parameters
// the first parameter of the return is a boolean represents whether the permission is assigned or not
// the second is an error in case of any
// in case the role does not exists, an error is returned
// in case the permission does not exists, an error is returned
func (a *Authority) CheckRolePermission(roleSlug string, permSlug string) (bool, error) {
	// find the role
	var role Role
	res := a.DB.Where("slug = ?", roleSlug).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, ErrRoleNotFound
		}
		return false, res.Error
	}

	// find the permission
	var perm Permission
	res = a.DB.Where("slug = ?", permSlug).First(&perm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, ErrPermissionNotFound
		}
		return false, res.Error
	}

	// find the rolePermission
	var rolePermission RolePermission
	res = a.DB.Where("role_id = ?", role.ID).Where("permission_id = ?", perm.ID).First(&rolePermission)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, res.Error
	}

	return true, nil
}

// Revokes a user's role
// it returns a error in case of any
// in case the role does not exists, an error is returned
func (a *Authority) RevokeUserRole(userID interface{}, roleSlug string) error {
	userIDStr := fmt.Sprintf("%v", userID)
	// find the role
	var role Role
	res := a.DB.Where("slug = ?", roleSlug).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}
		return res.Error
	}

	// revoke the role
	rRes := a.DB.Where("user_id = ?", userIDStr).Where("role_id = ?", role.ID).Delete(UserRole{})
	if rRes.Error != nil {
		return rRes.Error
	}

	return nil
}

// Revokes a roles's permission
// it returns a error in case of any
// in case the role does not exists, an error is returned
// in case the permission does not exists, an error is returned
func (a *Authority) RevokeRolePermission(roleSlug string, permSlug string) error {
	// find the role
	var role Role
	res := a.DB.Where("slug = ?", roleSlug).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}
		return res.Error
	}

	// find the permission
	var perm Permission
	res = a.DB.Where("slug = ?", permSlug).First(&perm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrPermissionNotFound
		}
		return res.Error
	}

	// revoke the permission
	rRes := a.DB.Where("role_id = ?", role.ID).Where("permission_id = ?", perm.ID).Delete(RolePermission{})
	if rRes.Error != nil {
		return rRes.Error
	}

	return nil
}

// Returns all stored roles
// it returns an error in case of any
func (a *Authority) GetAllRoles() ([]Role, error) {
	var roles []Role
	res := a.DB.Find(&roles)
	if res.Error != nil {
		return nil, res.Error
	}

	return roles, nil
}

// Returns all user assigned roles
// it returns an error in case of any
func (a *Authority) GetUserRoles(userID interface{}) ([]Role, error) {
	userIDStr := fmt.Sprintf("%v", userID)
	var userRoles []UserRole
	res := a.DB.Where("user_id = ?", userIDStr).Find(&userRoles)
	if res.Error != nil {
		return nil, res.Error
	}

	var roleIDs []interface{}
	for _, r := range userRoles {
		roleIDs = append(roleIDs, r.RoleID)
	}

	var roles []Role
	res = a.DB.Where("id IN (?)", roleIDs).Find(&roles)
	if res.Error != nil {
		return nil, res.Error
	}

	return roles, nil
}

// Returns all role assigned permissions
// it returns an error in case of any
func (a *Authority) GetRolePermissions(roleSlug string) ([]Permission, error) {
	var role Role
	res := a.DB.Where("slug = ?", roleSlug).Find(&role)
	if res.Error != nil {
		return nil, res.Error
	}

	var rolePerms []RolePermission
	res = a.DB.Where("role_id = ?", role.ID).Find(&rolePerms)
	if res.Error != nil {
		return nil, res.Error
	}
	var permIDs []interface{}
	for _, rolePerm := range rolePerms {
		permIDs = append(permIDs, rolePerm.PermissionID)
	}

	var perms []Permission
	res = a.DB.Where("id IN (?)", permIDs).Find(&perms)
	if res.Error != nil {
		return nil, res.Error
	}

	return perms, nil
}

// Returns all stored permissions
// it returns an error in case of any
func (a *Authority) GetAllPermissions() ([]Permission, error) {
	var perms []Permission
	res := a.DB.Find(&perms)
	if res.Error != nil {
		return nil, res.Error
	}

	return perms, nil
}

// Deletes a given role even if it's has assigned permissions
// it first deassign the permissions and then proceed with deleting the role
// it accepts the role slug as a parameter
// it returns an error in case of any
// if the role is assigned to a user it returns an error
func (a *Authority) DeleteRole(roleSlug string) error {
	// find the role
	var role Role
	res := a.DB.Where("slug = ?", roleSlug).First(&role)
	if res.Error != nil {
		return res.Error
	}

	// check if the role is assigned to a user
	var c int64
	res = a.DB.Model(UserRole{}).Where("role_id = ?", role.ID).Count(&c)
	if res.Error != nil {
		return res.Error
	}

	if c != 0 {
		// role is assigned
		return ErrRoleInUse
	}
	tx := a.DB.Begin()
	// revoke the assignment of permissions before deleting the role
	dRes := tx.Where("role_id = ?", role.ID).Delete(RolePermission{})
	if dRes.Error != nil {
		tx.Rollback()
		return dRes.Error
	}

	// delete the role
	dRes = a.DB.Where("slug = ?", roleSlug).Delete(Role{})
	if dRes.Error != nil {
		tx.Rollback()
		return dRes.Error
	}

	return tx.Commit().Error
}

// Deletes a given permission
// it accepts the permission slug as a parameter
// it returns an error in case of any
// if the permission is assigned to a role it returns an error
func (a *Authority) DeletePermission(permSlug string) error {
	// find the permission
	var perm Permission
	res := a.DB.Where("slug = ?", permSlug).First(&perm)
	if res.Error != nil {
		return res.Error
	}

	// check if the permission is assigned to a role
	var rolePermission RolePermission
	res = a.DB.Where("permission_id = ?", perm.ID).First(&rolePermission)
	if res.Error != nil && !errors.Is(res.Error, gorm.ErrRecordNotFound) {
		return res.Error
	}

	if res.Error == nil {
		return ErrPermissionInUse
	}

	// delete the permission
	dRes := a.DB.Where("slug = ?", permSlug).Delete(Permission{})
	if dRes.Error != nil {
		return dRes.Error
	}

	return nil
}

// Begin a transaction session
func (a *Authority) BeginTX() *Authority {
	tx = options.DB.Begin()
	newAuth := newInstance(Options{
		TablesPrefix: options.TablesPrefix,
		DB:           tx,
	})

	return newAuth
}

// Rolback previous queries
func (a *Authority) Rollback() error {
	return tx.Rollback().Error
}

// Commit queries to the database
func (a *Authority) Commit() error {
	return tx.Commit().Error
}

func migrateTables(db *gorm.DB) {
	db.AutoMigrate(&Role{})
	db.AutoMigrate(&Permission{})
	db.AutoMigrate(&RolePermission{})
	db.AutoMigrate(&UserRole{})
}
