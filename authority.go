package authority

import (
	"errors"

	"gorm.io/gorm"
)

// Authority helps deal with permissions
type Authority struct {
	DB *gorm.DB
}

// Options has the options for initiating the package
type Options struct {
	TablesPrefix string
	DB           *gorm.DB
}

var (
	ErrPermissionInUse     = errors.New("cannot delete assigned permission")
	ErrPermissionNotFound  = errors.New("permission not found")
	ErrRoleAlreadyAssigned = errors.New("this role is already assigned to the user")
	ErrRoleInUse           = errors.New("cannot delete assigned role")
	ErrRoleNotFound        = errors.New("role not found")
)

var tablePrefix string

var auth *Authority

// New initiates authority
func New(opts Options) *Authority {
	tablePrefix = opts.TablesPrefix
	auth = &Authority{
		DB: opts.DB,
	}

	migrateTables(opts.DB)
	return auth
}

// Resolve returns the initiated instance
func Resolve() *Authority {
	return auth
}

// CreateRole stores a role in the database
// it accepts the role name. it returns an error
// in case of any
func (a *Authority) CreateRole(roleName string) error {
	var dbRole Role
	res := a.DB.Where("name = ?", roleName).First(&dbRole)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			// create
			a.DB.Create(&Role{Name: roleName})
			return nil
		}
	}

	return res.Error
}

// CreatePermission stores a permission in the database
// it accepts the permission name. it returns an error
// in case of any
func (a *Authority) CreatePermission(permName string) error {
	var dbPerm Permission
	res := a.DB.Where("name = ?", permName).First(&dbPerm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			// create
			a.DB.Create(&Permission{Name: permName})
			return nil
		}
	}

	return res.Error
}

// AssignPermissions assigns a group of permissions to a given role
// it accepts in the first parameter the role name, it returns an error if there is not matching record
// of the role name in the database.
// the second parameter is a slice of strings which represents a group of permissions to be assigned to the role
// if any of these permissions doesn't have a matching record in the database the operations stops, changes reverted
// and error is returned
// in case of success nothing is returned
func (a *Authority) AssignPermissions(roleName string, permNames []string) error {
	// get the role id
	var role Role
	rRes := a.DB.Where("name = ?", roleName).First(&role)
	if rRes.Error != nil {
		if errors.Is(rRes.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}

	}

	var perms []Permission
	// get the permissions ids
	for _, permName := range permNames {
		var perm Permission
		pRes := a.DB.Where("name = ?", permName).First(&perm)
		if pRes.Error != nil {
			if errors.Is(pRes.Error, gorm.ErrRecordNotFound) {
				return ErrPermissionNotFound
			}

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

// AssignRole assigns a given role to a user
// the first parameter is the user id, the second parameter is the role name
// if the role name doesn't have a matching record in the data base an error is returned
// if the user have already a role assigned to him an error is returned
func (a *Authority) AssignRole(userID uint, roleName string) error {
	// make sure the role exist
	var role Role
	res := a.DB.Where("name = ?", roleName).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}
	}

	// check if the role is already assigned
	var userRole UserRole
	res = a.DB.Where("user_id = ?", userID).Where("role_id = ?", role.ID).First(&userRole)
	if res.Error == nil {
		//found a record, this role is already assigned to the same user
		return ErrRoleAlreadyAssigned
	}

	// assign the role
	a.DB.Create(&UserRole{UserID: userID, RoleID: role.ID})

	return nil
}

// CheckRole checks if a role is assigned to a user
// it accepts the user id as the first parameter
// the role as the second parameter
// it returns an error if the role is not present in database
func (a *Authority) CheckRole(userID uint, roleName string) (bool, error) {
	// find the role
	var role Role
	res := a.DB.Where("name = ?", roleName).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, ErrRoleNotFound
		}

	}

	// check if the role is a assigned
	var userRole UserRole
	res = a.DB.Where("user_id = ?", userID).Where("role_id = ?", role.ID).First(&userRole)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, nil
		}

	}

	return true, nil
}

// CheckPermission checks if a permission is assigned to the role that's assigned to the user.
// it accepts the user id as the first parameter
// the permission as the second parameter
// it returns an error if the permission is not present in the database
func (a *Authority) CheckPermission(userID uint, permName string) (bool, error) {
	// the user role
	var userRoles []UserRole
	res := a.DB.Where("user_id = ?", userID).Find(&userRoles)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, nil
		}
	}

	//prepare an array of role ids
	var roleIDs []uint
	for _, r := range userRoles {
		roleIDs = append(roleIDs, r.RoleID)
	}

	// find the permission
	var perm Permission
	res = a.DB.Where("name = ?", permName).First(&perm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, ErrPermissionNotFound
		}

	}

	// find the role permission
	var rolePermission RolePermission
	res = a.DB.Where("role_id IN (?)", roleIDs).Where("permission_id = ?", perm.ID).First(&rolePermission)
	if res.Error != nil {
		return false, nil
	}

	return true, nil
}

// CheckRolePermission checks if a role has the permission assigned
// it accepts the role as the first parameter
// it accepts the permission as the second parameter
// it returns an error if the role is not present in database
// it returns an error if the permission is not present in database
func (a *Authority) CheckRolePermission(roleName string, permName string) (bool, error) {
	// find the role
	var role Role
	res := a.DB.Where("name = ?", roleName).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, ErrRoleNotFound
		}

	}

	// find the permission
	var perm Permission
	res = a.DB.Where("name = ?", permName).First(&perm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, ErrPermissionNotFound
		}

	}

	// find the rolePermission
	var rolePermission RolePermission
	res = a.DB.Where("role_id = ?", role.ID).Where("permission_id = ?", perm.ID).First(&rolePermission)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, nil
		}

	}

	return true, nil
}

// RevokeRole revokes a user's role
// it returns a error in case of any
func (a *Authority) RevokeRole(userID uint, roleName string) error {
	// find the role
	var role Role
	res := a.DB.Where("name = ?", roleName).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}

	}

	// revoke the role
	a.DB.Where("user_id = ?", userID).Where("role_id = ?", role.ID).Delete(UserRole{})

	return nil
}

// RevokePermission revokes a permission from the user's assigned role
// it returns an error in case of any
func (a *Authority) RevokePermission(userID uint, permName string) error {
	// revoke the permission from all roles of the user
	// find the user roles
	var userRoles []UserRole
	res := a.DB.Where("user_id = ?", userID).Find(&userRoles)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return nil
		}

	}

	// find the permission
	var perm Permission
	res = a.DB.Where("name = ?", permName).First(&perm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrPermissionNotFound
		}

	}

	for _, r := range userRoles {
		// revoke the permission
		a.DB.Where("role_id = ?", r.RoleID).Where("permission_id = ?", perm.ID).Delete(RolePermission{})
	}

	return nil
}

// RevokeRolePermission revokes a permission from a given role
// it returns an error in case of any
func (a *Authority) RevokeRolePermission(roleName string, permName string) error {
	// find the role
	var role Role
	res := a.DB.Where("name = ?", roleName).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}

	}

	// find the permission
	var perm Permission
	res = a.DB.Where("name = ?", permName).First(&perm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrPermissionNotFound
		}

	}

	// revoke the permission
	a.DB.Where("role_id = ?", role.ID).Where("permission_id = ?", perm.ID).Delete(RolePermission{})

	return nil
}

// GetRoles returns all stored roles
func (a *Authority) GetRoles() ([]string, error) {
	var result []string
	var roles []Role
	a.DB.Find(&roles)

	for _, role := range roles {
		result = append(result, role.Name)
	}

	return result, nil
}

// GetUserRoles returns all user assigned roles
func (a *Authority) GetUserRoles(userID uint) ([]string, error) {
	var result []string
	var userRoles []UserRole
	a.DB.Where("user_id = ?", userID).Find(&userRoles)

	for _, r := range userRoles {
		var role Role
		// for every user role get the role name
		res := a.DB.Where("id = ?", r.RoleID).Find(&role)
		if res.Error == nil {
			result = append(result, role.Name)
		}
	}

	return result, nil
}

// GetPermissions returns all stored permissions
func (a *Authority) GetPermissions() ([]string, error) {
	var result []string
	var perms []Permission
	a.DB.Find(&perms)

	for _, perm := range perms {
		result = append(result, perm.Name)
	}

	return result, nil
}

// DeleteRole deletes a given role
// if the role is assigned to a user it returns an error
func (a *Authority) DeleteRole(roleName string) error {
	// find the role
	var role Role
	res := a.DB.Where("name = ?", roleName).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}

	}

	// check if the role is assigned to a user
	var userRole UserRole
	res = a.DB.Where("role_id = ?", role.ID).First(&userRole)
	if res.Error == nil {
		// role is assigned
		return ErrRoleInUse
	}

	// revoke the assignment of permissions before deleting the role
	a.DB.Where("role_id = ?", role.ID).Delete(RolePermission{})

	// delete the role
	a.DB.Where("name = ?", roleName).Delete(Role{})

	return nil
}

// DeletePermission deletes a given permission
// if the permission is assigned to a role it returns an error
func (a *Authority) DeletePermission(permName string) error {
	// find the permission
	var perm Permission
	res := a.DB.Where("name = ?", permName).First(&perm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrPermissionNotFound
		}

	}

	// check if the permission is assigned to a role
	var rolePermission RolePermission
	res = a.DB.Where("permission_id = ?", perm.ID).First(&rolePermission)
	if res.Error == nil {
		// role is assigned
		return ErrPermissionInUse
	}

	// delete the permission
	a.DB.Where("name = ?", permName).Delete(Permission{})

	return nil
}

func migrateTables(db *gorm.DB) {
	db.AutoMigrate(&Role{})
	db.AutoMigrate(&Permission{})
	db.AutoMigrate(&RolePermission{})
	db.AutoMigrate(&UserRole{})
}
