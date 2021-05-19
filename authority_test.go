package authority_test

import (
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/harranali/authority"
	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB

func TestMain(m *testing.M) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	var dsn string
	if os.Getenv("env") == "testing" {
		fmt.Println("preparing testing config...")
		dsn = fmt.Sprintf("root:%s@tcp(127.0.0.1:3306)/db_test?charset=utf8mb4&parseTime=True&loc=Local",
			os.Getenv("ROOT_PASSWORD"))
	} else {
		dsn = "root:@tcp(127.0.0.1:3306)/db_test?charset=utf8mb4&parseTime=True&loc=Local"
	}

	db, _ = gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})

	// call flag.Parse() here if TestMain uses flags
	os.Exit(m.Run())
}

func TestCreateRole(t *testing.T) {

	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// test create role
	err := auth.CreateRole("role-a")
	if err != nil {
		t.Error("an error was not expected while creating role ", err)
	}

	var c int64
	res := db.Model(authority.Role{}).Where("name = ?", "role-a").Count(&c)
	if res.Error != nil {
		t.Error("unexpected error while storing role: ", err)
	}
	if c == 0 {
		t.Error("role has not been stored")
	}

	// test duplicated entries
	auth.CreateRole("role-a")
	auth.CreateRole("role-a")
	auth.CreateRole("role-a")
	db.Model(authority.Role{}).Where("name = ?", "role-a").Count(&c)
	if c > 1 {
		t.Error("unexpected duplicated entries for role")
	}

	// clean up
	db.Where("name = ?", "role-a").Delete(authority.Role{})
}

func TestCreatePermission(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// test create permission
	err := auth.CreatePermission("permission-a")
	if err != nil {
		t.Error("an error was not expected while creating permision ", err)
	}

	var c int64
	res := db.Model(authority.Permission{}).Where("name = ?", "permission-a").Count(&c)
	if res.Error != nil {
		t.Error("unexpected error while storing permission: ", err)
	}
	if c == 0 {
		t.Error("permission has not been stored")
	}

	// test duplicated entries
	auth.CreatePermission("permission-a")
	auth.CreatePermission("permission-a")
	auth.CreatePermission("permission-a")
	db.Model(authority.Role{}).Where("name = ?", "permission-a").Count(&c)
	if c > 1 {
		t.Error("unexpected duplicated entries for permission")
	}

	// clean up
	db.Where("name = ?", "permission-a").Delete(authority.Permission{})
}

func TestAssignPermission(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role
	err := auth.CreateRole("role-a")
	if err != nil {
		t.Error("unexpected error while creating role.", err)
	}

	// second test create permissions
	err = auth.CreatePermission("permission-a")
	if err != nil {
		t.Error("unexpected error while creating permission to be assigned.", err)
	}
	err = auth.CreatePermission("permission-b")
	if err != nil {
		t.Error("unexpected error while creating permission to be assigned.", err)
	}

	// assign the permissions
	err = auth.AssignPermissions("role-a", []string{"permission-a", "permission-b"})
	if err != nil {
		t.Error("unexpected error while assigning permissions.", err)
	}

	// assign to missing role
	err = auth.AssignPermissions("role-aa", []string{"permission-a", "permission-b"})
	if err == nil {
		t.Error("expecting error when assigning to missing role")
	}

	// assign to missing permission
	err = auth.AssignPermissions("role-a", []string{"permission-aa"})
	if err == nil {
		t.Error("expecting error when assigning missing permission")
	}

	var r authority.Role
	db.Where("name = ?", "role-a").First(&r)
	var rolePermsCount int64
	db.Model(authority.RolePermission{}).Where("role_id = ?", r.ID).Count(&rolePermsCount)
	if rolePermsCount != 2 {
		t.Error("failed assigning roles to permission")
	}

	// clean up
	db.Where("role_id = ?", r.ID).Delete(authority.RolePermission{})
	db.Where("name = ?", "role-a").Delete(authority.Role{})
	db.Where("name = ?", "permission-a").Delete(authority.Permission{})
	db.Where("name = ?", "permission-b").Delete(authority.Permission{})
}

func TestAssignRole(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role
	err := auth.CreateRole("role-a")
	if err != nil {
		t.Error("unexpected error while creating role to be assigned.", err)
	}

	// assign the role
	err = auth.AssignRole(1, "role-a")
	if err != nil {
		t.Error("unexpected error while assigning role.", err)
	}

	// double assign the role
	err = auth.AssignRole(1, "role-a")
	if err == nil {
		t.Error("expecting an error when assign a role to user more than one time")
	}

	// assign a second role
	auth.CreateRole("role-b")
	err = auth.AssignRole(1, "role-b")
	if err != nil {
		t.Error("un expected error when assigning a second role. ", err)
	}

	// assign missing role
	err = auth.AssignRole(1, "role-aa")
	if err == nil {
		t.Error("expecting an error when assigning role to a user")
	}

	var r authority.Role
	db.Where("name = ?", "role-a").First(&r)
	var userRoles int64
	db.Model(authority.UserRole{}).Where("role_id = ?", r.ID).Count(&userRoles)
	if userRoles != 1 {
		t.Error("failed assigning roles to permission")
	}

	//clean up
	db.Where("user_id = ?", 1).Delete(authority.UserRole{})
	db.Where("name = ?", "role-a").Delete(authority.Role{})
	db.Where("name = ?", "role-b").Delete(authority.Role{})
}

func TestCheckRole(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role and assign it to a user
	err := auth.CreateRole("role-a")
	if err != nil {
		t.Error("unexpected error while creating role to be assigned.", err)
	}
	// assign the role
	err = auth.AssignRole(1, "role-a")
	if err != nil {
		t.Error("unexpected error while assigning role.", err)
	}

	// assert
	ok, err := auth.CheckRole(1, "role-a")
	if err != nil {
		t.Error("unexpected error while checking user for assigned role.", err)
	}
	if !ok {
		t.Error("failed to check assinged role")
	}

	// check aa missing role
	_, err = auth.CheckRole(1, "role-aa")
	if err == nil {
		t.Error("expecting an error when checking a missing role")
	}

	// check a missing user
	ok, _ = auth.CheckRole(11, "role-a")
	if ok {
		t.Error("expecting false when checking missing role")
	}

	// clean up
	var r authority.Role
	db.Where("name = ?", "role-a").First(&r)
	db.Where("role_id = ?", r.ID).Delete(authority.UserRole{})
	db.Where("name = ?", "role-a").Delete(authority.Role{})
}

func TestCheckPermission(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role
	err := auth.CreateRole("role-a")
	if err != nil {
		t.Error("unexpected error while creating role.", err)
	}

	//create permissions
	err = auth.CreatePermission("permission-a")
	if err != nil {
		t.Error("unexpected error while creating permission to be assigned.", err)
	}
	err = auth.CreatePermission("permission-b")
	if err != nil {
		t.Error("unexpected error while creating permission to be assigned.", err)
	}

	// assign the permissions
	err = auth.AssignPermissions("role-a", []string{"permission-a", "permission-b"})
	if err != nil {
		t.Error("unexpected error while assigning permissions.", err)
	}

	// test when no role is a ssigned
	ok, err := auth.CheckPermission(1, "permission-a")
	if err != nil {
		t.Error("expecting error to be nil when no role is assigned")
	}
	if ok {
		t.Error("expecting false to be returned when no role is assigned")
	}

	// assign the role
	err = auth.AssignRole(1, "role-a")
	if err != nil {
		t.Error("unexpected error while assigning role.", err)
	}

	// test a permission of an assigned role
	ok, err = auth.CheckPermission(1, "permission-a")
	if err != nil {
		t.Error("unexpected error while checking permission of a user.", err)
	}
	if !ok {
		t.Error("expecting true to be returned")
	}

	// check when user does not have roles
	ok, _ = auth.CheckPermission(111, "permission-a")
	if ok {
		t.Error("expecting an false when checking permission of not assigned  user")
	}

	// test assigning missing permission
	_, err = auth.CheckPermission(1, "permission-aa")
	if err == nil {
		t.Error("expecting an error when checking a missing permission")
	}

	// check for an exist but not assigned permission
	auth.CreatePermission("permission-c")
	ok, _ = auth.CheckPermission(1, "permission-c")
	if ok {
		t.Error("expecting false when checking for not assigned permissions")
	}

	// clean up
	var r authority.Role
	db.Where("name = ?", "role-a").First(&r)
	db.Where("role_id = ?", r.ID).Delete(authority.UserRole{})
	db.Where("role_id = ?", r.ID).Delete(authority.RolePermission{})
	db.Where("name = ?", "permission-a").Delete(authority.Permission{})
	db.Where("name = ?", "permission-b").Delete(authority.Permission{})
	db.Where("name = ?", "permission-c").Delete(authority.Permission{})
	db.Where("name = ?", "role-a").Delete(authority.Role{})
}

func TestCheckRolePermission(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role
	err := auth.CreateRole("role-a")
	if err != nil {
		t.Error("unexpected error while creating role.", err)
	}

	// second test create permissions
	err = auth.CreatePermission("permission-a")
	if err != nil {
		t.Error("unexpected error while creating permission to be assigned.", err)
	}
	err = auth.CreatePermission("permission-b")
	if err != nil {
		t.Error("unexpected error while creating permission to be assigned.", err)
	}

	// third assign the permissions
	err = auth.AssignPermissions("role-a", []string{"permission-a", "permission-b"})
	if err != nil {
		t.Error("unexpected error while assigning permissions.", err)
	}

	// check the role permission
	ok, err := auth.CheckRolePermission("role-a", "permission-a")
	if err != nil {
		t.Error("unexpected error while checking role permission.", err)
	}
	if !ok {
		t.Error("failed assigning roles to permission check")
	}

	// check a missing role
	_, err = auth.CheckRolePermission("role-aa", "permission-a")
	if err == nil {
		t.Error("expecting an error when checking permisson of missing role")
	}

	// check with missing permission
	_, err = auth.CheckRolePermission("role-a", "permission-aa")
	if err == nil {
		t.Error("expecting an error when checking missing permission")
	}

	// check with not assigned permission
	auth.CreatePermission("permission-c")
	ok, _ = auth.CheckRolePermission("role-a", "permission-c")
	if ok {
		t.Error("expecting false when checking a missing permission")
	}

	//clean up
	var r authority.Role
	db.Where("name = ?", "role-a").First(&r)
	db.Where("role_id = ?", r.ID).Delete(authority.RolePermission{})
	db.Where("name = ?", "permission-a").Delete(authority.Permission{})
	db.Where("name = ?", "permission-b").Delete(authority.Permission{})
	db.Where("name = ?", "permission-c").Delete(authority.Permission{})
	db.Where("name = ?", "role-a").Delete(authority.Role{})
}

func TestRevokeRole(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role
	err := auth.CreateRole("role-a")
	if err != nil {
		t.Error("unexpected error while creating role.", err)
	}

	// assign the role
	err = auth.AssignRole(1, "role-a")
	if err != nil {
		t.Error("unexpected error while assigning role.", err)
	}

	//test
	err = auth.RevokeRole(1, "role-a")
	if err != nil {
		t.Error("unexpected error revoking user role.", err)
	}
	// revoke missing role
	err = auth.RevokeRole(1, "role-aa")
	if err == nil {
		t.Error("expecting error when revoking a missing role")
	}

	var c int64
	db.Model(authority.UserRole{}).Where("user_id = ?", 1).Count(&c)
	if c != 0 {
		t.Error("failed assert revoking user role")
	}

	var r authority.Role
	db.Where("name = ?", "role-a").First(&r)
	db.Where("role_id = ?", r.ID).Delete(authority.UserRole{})
	db.Where("name = ?", "role-a").Delete(authority.Role{})
}

func TestRevokePermission(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role
	err := auth.CreateRole("role-a")
	if err != nil {
		t.Error("unexpected error while creating role.", err)
	}
	// second test create permissions
	err = auth.CreatePermission("permission-a")
	if err != nil {
		t.Error("unexpected error while creating permission to be assigned.", err)
	}
	err = auth.CreatePermission("permission-b")
	if err != nil {
		t.Error("unexpected error while creating permission to be assigned.", err)
	}

	// third assign the permissions
	err = auth.AssignPermissions("role-a", []string{"permission-a", "permission-b"})
	if err != nil {
		t.Error("unexpected error while assigning permissions.", err)
	}

	// assign the role
	err = auth.AssignRole(1, "role-a")
	if err != nil {
		t.Error("unexpected error while assigning role.", err)
	}

	// case: user not assigned role
	err = auth.RevokePermission(11, "permission-a")
	if err != nil {
		t.Error("expecting error to be nil", err)
	}

	// test
	err = auth.RevokePermission(1, "permission-a")
	if err != nil {
		t.Error("unexpected error while revoking role permissions.", err)
	}

	// revoke missing permissin
	err = auth.RevokePermission(1, "permission-aa")
	if err == nil {
		t.Error("expecting error when revoking a missing permission")
	}

	// assert, count assigned permission, should be one
	var r authority.Role
	db.Where("name = ?", "role-a").First(&r)
	var c int64
	db.Model(authority.RolePermission{}).Where("role_id = ?", r.ID).Count(&c)
	if c != 1 {
		t.Error("failed assert revoking permission role")
	}

	// clean up
	db.Where("role_id = ?", r.ID).Delete(authority.UserRole{})
	db.Where("role_id = ?", r.ID).Delete(authority.RolePermission{})
	db.Where("name = ?", "permission-a").Delete(authority.Permission{})
	db.Where("name = ?", "permission-b").Delete(authority.Permission{})
	db.Where("name = ?", "role-a").Delete(authority.Role{})
}

func TestRevokeRolePermission(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role
	err := auth.CreateRole("role-a")
	if err != nil {
		t.Error("unexpected error while creating role.", err)
	}
	// second test create permissions
	err = auth.CreatePermission("permission-a")
	if err != nil {
		t.Error("unexpected error while creating permission to be assigned.", err)
	}
	err = auth.CreatePermission("permission-b")
	if err != nil {
		t.Error("unexpected error while creating permission to be assigned.", err)
	}

	// third assign the permissions
	err = auth.AssignPermissions("role-a", []string{"permission-a", "permission-b"})
	if err != nil {
		t.Error("unexpected error while assigning permissions.", err)
	}

	// test revoke missing role
	err = auth.RevokeRolePermission("role-aa", "permission-a")
	if err == nil {
		t.Error("expecting an error when revoking a missing role")
	}

	// test revoke missing permission
	err = auth.RevokeRolePermission("role-a", "permission-aa")
	if err == nil {
		t.Error("expecting an error when revoking a missing permission")
	}

	err = auth.RevokeRolePermission("role-a", "permission-a")
	if err != nil {
		t.Error("unexpected error while revoking role permissions.", err)
	}
	// assert, count assigned permission, should be one
	var r authority.Role
	db.Where("name = ?", "role-a").First(&r)
	var c int64
	db.Model(authority.RolePermission{}).Where("role_id = ?", r.ID).Count(&c)
	if c != 1 {
		t.Error("failed assert revoking permission role")
	}

	// clean up
	db.Where("role_id = ?", r.ID).Delete(authority.RolePermission{})
	db.Where("name = ?", "permission-a").Delete(authority.Permission{})
	db.Where("name = ?", "permission-b").Delete(authority.Permission{})
	db.Where("name = ?", "role-a").Delete(authority.Role{})
}

func TestGetRoles(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create roles
	err := auth.CreateRole("role-a")
	if err != nil {
		t.Error("unexpected error while creating role.", err)
	}
	err = auth.CreateRole("role-b")
	if err != nil {
		t.Error("unexpected error while creating role.", err)
	}

	// test
	roles, err := auth.GetRoles()
	// check
	if len(roles) != 2 {
		t.Error("failed assert getting roles")
	}
	db.Where("name = ?", "role-a").Delete(authority.Role{})
	db.Where("name = ?", "role-b").Delete(authority.Role{})
}

func TestGetPermissions(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create permission
	err := auth.CreatePermission("permission-a")
	if err != nil {
		t.Error("unexpected error while creating permission.", err)
	}
	err = auth.CreatePermission("permission-b")
	if err != nil {
		t.Error("unexpected error while creating permission.", err)
	}

	// test
	perms, err := auth.GetPermissions()
	// check
	if len(perms) != 2 {
		t.Error("failed assert getting permission")
	}
	db.Where("name = ?", "permission-a").Delete(authority.Permission{})
	db.Where("name = ?", "permission-b").Delete(authority.Permission{})
}

func TestDeleteRole(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	err := auth.CreateRole("role-a")
	if err != nil {
		t.Error("unexpected error while creating role.", err)
	}

	// test delete a missing role
	err = auth.DeleteRole("role-aa")
	if err == nil {
		t.Error("expecting an error when deleting a missing role")
	}

	// test delete an assigned role
	auth.AssignRole(1, "role-a")
	err = auth.DeleteRole("role-a")
	if err == nil {
		t.Error("expecting an error when deleting an assigned role")
	}
	auth.RevokeRole(1, "role-a")

	err = auth.DeleteRole("role-a")
	if err != nil {
		t.Error("unexpected error while deleting role.", err)
	}

	var c int64
	db.Model(authority.Role{}).Count(&c)
	if c != 0 {
		t.Error("failed assert deleting role")
	}
}

func TestDeletePermission(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	err := auth.CreatePermission("permission-a")
	if err != nil {
		t.Error("unexpected error while creating permission.", err)
	}

	// delete missing permission
	err = auth.DeletePermission("permission-aa")
	if err == nil {
		t.Error("expecting an error when deleting a missing permission")
	}

	// delete an assigned permission
	auth.CreateRole("role-a")
	auth.AssignPermissions("role-a", []string{"permission-a"})

	// delete assinged permission
	err = auth.DeletePermission("permission-a")
	if err == nil {
		t.Error("expecting an error when deleting assigned permission")
	}

	auth.RevokeRolePermission("role-a", "permission-a")

	err = auth.DeletePermission("permission-a")
	if err != nil {
		t.Error("unexpected error while deleting permission.", err)
	}

	var c int64
	db.Model(authority.Permission{}).Count(&c)
	if c != 0 {
		t.Error("failed assert deleting permission")
	}

	// clean up
	auth.DeleteRole("role-a")
}

func TestGetUserRoles(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role
	auth.CreateRole("role-a")
	auth.CreateRole("role-b")
	auth.AssignRole(1, "role-a")
	auth.AssignRole(1, "role-b")

	roles, _ := auth.GetUserRoles(1)
	if len(roles) != 2 {
		t.Error("expeting two roles to be returned")
	}

	if !sliceHasString(roles, "role-a") {
		t.Error("missing role in returned roles")
	}

	if !sliceHasString(roles, "role-b") {
		t.Error("missing role in returned roles")
	}

	db.Where("user_id = ?", 1).Delete(authority.UserRole{})
	db.Where("name = ?", "role-a").Delete(authority.Role{})
	db.Where("name = ?", "role-b").Delete(authority.Role{})
}

func sliceHasString(s []string, val string) bool {
	for _, v := range s {
		if v == val {
			return true
		}
	}

	return false
}
