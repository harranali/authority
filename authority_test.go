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
	err := auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("an error was not expected while creating role ", err)
	}

	var c int64
	res := db.Model(authority.Role{}).Where("slug = ?", "role-a").Count(&c)
	if res.Error != nil {
		t.Error("failed test create role", res.Error)
	}
	if c == 0 {
		t.Error("failed test create role ")
	}

	// test duplicated entries
	err = auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err == nil {
		t.Error("failed test create role")
	}

	t.Cleanup(func() {
		// clean up
		db.Where("slug = ?", "role-a").Delete(authority.Role{})
	})

}

func TestCreatePermission(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	err := auth.CreatePermission(authority.Permission{
		Name: "Permission A",
		Slug: "permission-a",
	})
	if err != nil {
		t.Error("failed test create permission", err)
	}

	var c int64
	res := db.Model(authority.Permission{}).Where("slug = ?", "permission-a").Count(&c)
	if res.Error != nil {
		t.Error("failed test create permission", res.Error)
	}
	if c != 1 {
		t.Error("permission has not been stored")
	}

	// test duplicated entries
	err = auth.CreatePermission(authority.Permission{
		Name: "Permission A",
		Slug: "permission-a",
	})
	if err == nil {
		t.Error("failed test create permission")
	}

	db.Model(authority.Role{}).Where("slug = ?", "permission-a").Count(&c)
	if c > 1 {
		t.Error("failed test create permission")
	}

	t.Cleanup(func() {
		// clean up
		db.Where("slug = ?", "permission-a").Delete(authority.Permission{})
	})

}

func TestAssignPermissionToRole(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})
	err := auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("failed test assign permission to role", err)
	}
	err = auth.CreatePermission(authority.Permission{
		Name: "Permission A",
		Slug: "permission-a",
	})
	if err != nil {
		t.Error("failed test assign permission to role", err)
	}
	err = auth.CreatePermission(authority.Permission{
		Name: "Permission B",
		Slug: "permission-b",
	})
	if err != nil {
		t.Error("failed test assign permission to role", err)
	}

	// assign the permissions
	err = auth.AssignPermissionsToRole("role-a", []string{"permission-a", "permission-b"})
	if err != nil {
		t.Error("failed test assign permission to role", err)
	}

	// assign to missing role
	err = auth.AssignPermissionsToRole("role-aa", []string{"permission-a", "permission-b"})
	if err == nil {
		t.Error("failed test assign permission to role")
	}

	// assign missing permission
	err = auth.AssignPermissionsToRole("role-a", []string{"permission-aa"})
	if err == nil {
		t.Error("failed test assign permission to role")
	}

	var r authority.Role
	db.Where("slug = ?", "role-a").First(&r)
	var rolePermsCount int64
	res := db.Model(authority.RolePermission{}).Where("role_id = ?", r.ID).Count(&rolePermsCount)
	if res.Error != nil {
		t.Error("failed test assign permission to role", res.Error)
	}
	if rolePermsCount != 2 {
		t.Error("failed test assign permission to role", err)
	}

	t.Cleanup(func() {
		// clean up
		db.Where("role_id = ?", r.ID).Delete(authority.RolePermission{})
		db.Where("slug = ?", "role-a").Delete(authority.Role{})
		db.Where("slug = ?", "permission-a").Delete(authority.Permission{})
		db.Where("slug = ?", "permission-b").Delete(authority.Permission{})
	})
}

func TestAssignRoleToUser(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})
	// first create a role
	err := auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("failed test assign role to user", err)
	}

	// assign the role
	err = auth.AssignRoleToUser(1, "role-a")
	if err != nil {
		t.Error("failed test assign role to user", err)
	}

	// double assign the role
	err = auth.AssignRoleToUser(1, "role-a")
	if err == nil {
		t.Error("failed test assign role to user")
	}

	// assign a second role
	auth.CreateRole(authority.Role{
		Name: "Role B",
		Slug: "role-b",
	})
	err = auth.AssignRoleToUser(1, "role-b")
	if err != nil {
		t.Error("failed test assign role to user", err)
	}

	// assign missing role
	err = auth.AssignRoleToUser(1, "role-aa")
	if err == nil {
		t.Error("failed test assign role to user")
	}

	var r authority.Role
	res := db.Where("slug = ?", "role-a").First(&r)
	if res.Error != nil {
		t.Error("failed test assign role to user", res.Error)
	}
	var userRoles int64
	res = db.Model(authority.UserRole{}).Where("user_id = ?", 1).Count(&userRoles)
	if res.Error != nil {
		t.Error("failed test assign role to user", err)
	}
	if userRoles != 2 {
		t.Error("failed test assign role to user")
	}

	t.Cleanup(func() {
		//clean up
		db.Where("user_id = ?", 1).Delete(authority.UserRole{})
		db.Where("slug = ?", "role-a").Delete(authority.Role{})
		db.Where("slug = ?", "role-b").Delete(authority.Role{})
	})

}

func TestCheckUserRole(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role and assign it to a user
	err := auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("failed test check user role", err)
	}
	// assign the role
	err = auth.AssignRoleToUser(1, "role-a")
	if err != nil {
		t.Error("failed test check user role", err)
	}

	// assert
	ok, err := auth.CheckUserRole(1, "role-a")
	if err != nil {
		t.Error("failed test check user role", err)
	}
	if !ok {
		t.Error("failed test check user role")
	}

	// check not exist assigned role
	err = auth.CreateRole(authority.Role{
		Name: "Role B",
		Slug: "role-b",
	})
	if err != nil {
		t.Error("failed test check user role", err)
	}
	ok, err = auth.CheckUserRole(1, "role-b")
	if err != nil {
		t.Error("failed test check user role", err)
	}
	if ok {
		t.Error("failed test check user role")
	}

	// check aa missing role
	_, err = auth.CheckUserRole(1, "role-aa")
	if err == nil {
		t.Error("failed test check user role")
	}

	// check a missing user
	ok, _ = auth.CheckUserRole(11, "role-a")
	if ok {
		t.Error("failed test check user role")
	}

	t.Cleanup(func() {
		// clean up
		var r authority.Role
		db.Where("slug = ?", "role-a").First(&r)
		db.Where("role_id = ?", r.ID).Delete(authority.UserRole{})
		db.Where("slug = ?", "role-a").Delete(authority.Role{})
		db.Where("slug = ?", "role-b").Delete(authority.Role{})
	})
}

// check user permission
func TestCheckUserPermission(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role
	err := auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("failed test check user permission", err)
	}

	//create permissions
	err = auth.CreatePermission(authority.Permission{
		Name: "Permission A",
		Slug: "permission-a",
	})
	if err != nil {
		t.Error("failed test check user permission", err)
	}
	err = auth.CreatePermission(authority.Permission{
		Name: "Permission B",
		Slug: "permission-b",
	})
	if err != nil {
		t.Error("failed test check user permission", err)
	}

	// assign the permissions
	err = auth.AssignPermissionsToRole("role-a", []string{"permission-a", "permission-b"})
	if err != nil {
		t.Error("failed test check user permission", err)
	}

	// test when no role is a ssigned
	ok, err := auth.CheckUserPermission(1, "permission-a")
	if err != nil {
		t.Error("failed test check user permission", err)
	}
	if ok {
		t.Error("failed test check user permission")
	}

	// assign the role
	err = auth.AssignRoleToUser(1, "role-a")
	if err != nil {
		t.Error("failed test check user permission", err)
	}

	// test a permission of an assigned role
	ok, err = auth.CheckUserPermission(1, "permission-a")
	if err != nil {
		t.Error("failed test check user permission", err)
	}
	if !ok {
		t.Error("failed test check user permission")
	}

	// test assigning missing permission
	_, err = auth.CheckUserPermission(1, "permission-aa")
	if err == nil {
		t.Error("failed test check user permission")
	}

	t.Cleanup(func() {
		// clean up
		var r authority.Role
		db.Where("slug = ?", "role-a").First(&r)
		db.Where("role_id = ?", r.ID).Delete(authority.UserRole{})
		db.Where("role_id = ?", r.ID).Delete(authority.RolePermission{})
		db.Where("slug = ?", "permission-a").Delete(authority.Permission{})
		db.Where("slug = ?", "permission-b").Delete(authority.Permission{})
		db.Where("slug = ?", "role-a").Delete(authority.Role{})
	})

}

func TestCheckRolePermission(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role
	err := auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("failed test check role permission", err)
	}

	// second test create permissions
	err = auth.CreatePermission(authority.Permission{
		Name: "Permission A",
		Slug: "permission-a",
	})
	if err != nil {
		t.Error("failed test check role permission", err)
	}
	err = auth.CreatePermission(authority.Permission{
		Name: "Permission B",
		Slug: "permission-b",
	})
	if err != nil {
		t.Error("failed test check role permission", err)
	}

	// third assign the permissions
	err = auth.AssignPermissionsToRole("role-a", []string{"permission-a", "permission-b"})
	if err != nil {
		t.Error("failed test check role permission", err)
	}

	// check the role permission
	ok, err := auth.CheckRolePermission("role-a", "permission-a")
	if err != nil {
		t.Error("failed test check role permission", err)
	}
	if !ok {
		t.Error("failed test check role permission")
	}

	// check a missing role
	_, err = auth.CheckRolePermission("role-aa", "permission-a")
	if err == nil {
		t.Error("failed test check role permission")
	}

	// check with missing permission
	_, err = auth.CheckRolePermission("role-a", "permission-aa")
	if err == nil {
		t.Error("failed test check role permission", err)
	}

	// check with not assigned permission
	auth.CreatePermission(authority.Permission{
		Name: "Permission C",
		Slug: "permission-c",
	})
	ok, _ = auth.CheckRolePermission("role-a", "permission-c")
	if ok {
		t.Error("failed test check role permission")
	}

	t.Cleanup(func() {
		//clean up
		var r authority.Role
		db.Where("slug = ?", "role-a").First(&r)
		db.Where("role_id = ?", r.ID).Delete(authority.RolePermission{})
		db.Where("slug = ?", "permission-a").Delete(authority.Permission{})
		db.Where("slug = ?", "permission-b").Delete(authority.Permission{})
		db.Where("slug = ?", "permission-c").Delete(authority.Permission{})
		db.Where("slug = ?", "role-a").Delete(authority.Role{})
	})

}

func TestRevokeUserRole(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role
	err := auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("failed test revoke user role", err)
	}

	// assign the role
	err = auth.AssignRoleToUser(1, "role-a")
	if err != nil {
		t.Error("failed test revoke user role", err)
	}

	//test
	err = auth.RevokeUserRole(1, "role-a")
	if err != nil {
		t.Error("failed test revoke user role", err)
	}

	// revoke missing role
	err = auth.RevokeUserRole(1, "role-aa")
	if err == nil {
		t.Error("failed test revoke user role")
	}

	var c int64
	db.Model(authority.UserRole{}).Where("user_id = ?", 1).Count(&c)
	if c != 0 {
		t.Error("failed test revoke user role")
	}

	t.Cleanup(func() {
		var r authority.Role
		db.Where("slug = ?", "role-a").First(&r)
		db.Where("role_id = ?", r.ID).Delete(authority.UserRole{})
		db.Where("slug = ?", "role-a").Delete(authority.Role{})
	})
}

func TestRevokeRolePermission(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create a role
	err := auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("failed test revoke role permission", err)
	}
	// second test create permissions
	err = auth.CreatePermission(authority.Permission{
		Name: "Permission A",
		Slug: "permission-a",
	})
	if err != nil {
		t.Error("failed test revoke role permission", err)
	}
	err = auth.CreatePermission(authority.Permission{
		Name: "Permission B",
		Slug: "permission-b",
	})
	if err != nil {
		t.Error("failed test revoke role permission", err)
	}

	// third assign the permissions
	err = auth.AssignPermissionsToRole("role-a", []string{"permission-a", "permission-b"})
	if err != nil {
		t.Error("failed test revoke role permission", err)
	}

	// test revoke missing role
	err = auth.RevokeRolePermission("role-aa", "permission-a")
	if err == nil {
		t.Error("failed test revoke role permission")
	}

	// test revoke missing permission
	err = auth.RevokeRolePermission("role-a", "permission-aa")
	if err == nil {
		t.Error("failed test revoke role permission")
	}

	err = auth.RevokeRolePermission("role-a", "permission-a")
	if err != nil {
		t.Error("failed test revoke role permission")
	}
	// assert, count assigned permission, should be one
	var r authority.Role
	res := db.Where("slug = ?", "role-a").First(&r)
	if res.Error != nil {
		t.Error("failed test revoke role permission", res.Error)
	}
	var c int64
	db.Model(authority.RolePermission{}).Where("role_id = ?", r.ID).Count(&c)
	if c != 1 {
		t.Error("failed test revoke role permission")
	}

	t.Cleanup(func() {
		// clean up
		db.Where("role_id = ?", r.ID).Delete(authority.RolePermission{})
		db.Where("slug = ?", "permission-a").Delete(authority.Permission{})
		db.Where("slug = ?", "permission-b").Delete(authority.Permission{})
		db.Where("slug = ?", "role-a").Delete(authority.Role{})
	})

}

func TestGetAllRoles(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create roles
	err := auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("failed test get roles", err)
	}
	err = auth.CreateRole(authority.Role{
		Name: "Role B",
		Slug: "role-b",
	})
	if err != nil {
		t.Error("failed test get roles", err)
	}

	// test
	roles, err := auth.GetAllRoles()
	if err != nil {
		t.Error("failed test get roles", err)
	}

	// check
	if len(roles) != 2 {
		t.Error("failed test get roles")
	}
	db.Where("slug = ?", "role-a").Delete(authority.Role{})
	db.Where("slug = ?", "role-b").Delete(authority.Role{})
}

func TestGetAllPermissions(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	// first create permission
	err := auth.CreatePermission(authority.Permission{
		Name: "Permission A",
		Slug: "permission-a",
	})
	if err != nil {
		t.Error("failed test get permissions", err)
	}
	err = auth.CreatePermission(authority.Permission{
		Name: "Permission B",
		Slug: "permission-b",
	})
	if err != nil {
		t.Error("failed test get permissions", err)
	}

	// test
	perms, err := auth.GetAllPermissions()
	// check
	if len(perms) != 2 {
		t.Error("failed test get permissions")
	}
	db.Where("slug = ?", "permission-a").Delete(authority.Permission{})
	db.Where("slug = ?", "permission-b").Delete(authority.Permission{})
}

func TestDeleteRole(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	err := auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("failed test delete role", err)
	}

	// test delete a missing role
	err = auth.DeleteRole("role-aa")
	if err == nil {
		t.Error("failed test delete role")
	}

	// test delete an assigned role
	err = auth.AssignRoleToUser(1, "role-a")
	if err != nil {
		t.Error("failed test delete role", err)
	}
	err = auth.DeleteRole("role-a")
	if err == nil {
		t.Error("failed test delete role")
	}
	err = auth.RevokeUserRole(1, "role-a")
	if err != nil {
		t.Error("failed test delete role", err)
	}
	err = auth.DeleteRole("role-a")
	if err != nil {
		t.Error("failed test delete role", err)
	}

	var c int64
	db.Model(authority.Role{}).Where("slug = ?", "role-a").Count(&c)
	if c != 0 {
		t.Error("failed test delete role")
	}
}

func TestDeletePermission(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	err := auth.CreatePermission(authority.Permission{
		Name: "Permission A",
		Slug: "permission-a",
	})
	if err != nil {
		t.Error("failed test delete permission", err)
	}

	// delete missing permission
	err = auth.DeletePermission("permission-aa")
	if err == nil {
		t.Error("failed test delete permission", err)
	}

	// delete an assigned permission
	auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	auth.AssignPermissionsToRole("role-a", []string{"permission-a"})

	// delete assinged permission
	err = auth.DeletePermission("permission-a")
	if err == nil {
		t.Error("failed test delete permission")
	}

	err = auth.RevokeRolePermission("role-a", "permission-a")
	if err != nil {
		t.Error("failed test delete permission", err)
	}

	err = auth.DeletePermission("permission-a")
	if err != nil {
		t.Error("failed test delete permission", err)
	}

	var c int64
	db.Model(authority.Permission{}).Count(&c)
	if c != 0 {
		t.Error("failed test delete permission")
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
	err := auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("failed test get user roles", err)
	}

	err = auth.CreateRole(authority.Role{
		Name: "Role B",
		Slug: "role-b",
	})
	if err != nil {
		t.Error("failed test get user roles", err)
	}
	err = auth.AssignRoleToUser(1, "role-a")
	if err != nil {
		t.Error("failed test get user roles", err)
	}
	err = auth.AssignRoleToUser(1, "role-b")
	if err != nil {
		t.Error("failed test get user roles", err)
	}

	roles, err := auth.GetUserRoles(1)
	if err != nil {
		t.Error("failed test get user roles", err)
	}

	if len(roles) != 2 {
		t.Error("failed test get user roles")
	}
	for _, role := range roles {
		if !(role.Slug == "role-a" || role.Slug == "role-b") {
			t.Error("failed test get user roles")
		}
	}

	db.Where("user_id = ?", 1).Delete(authority.UserRole{})
	db.Where("slug = ?", "role-a").Delete(authority.Role{})
	db.Where("slug = ?", "role-b").Delete(authority.Role{})
}

func TestGetRolePermissions(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})

	err := auth.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("failed test get role permissions", err)
	}
	err = auth.CreatePermission(authority.Permission{
		Name: "Permission A",
		Slug: "permission-a",
	})
	if err != nil {
		t.Error("failed test get role permissions", err)
	}
	err = auth.CreatePermission(authority.Permission{
		Name: "Permission B",
		Slug: "permission-b",
	})
	if err != nil {
		t.Error("failed test get role permissions", err)
	}
	err = auth.AssignPermissionsToRole("role-a", []string{"permission-a", "permission-b"})
	rolePermissions, err := auth.GetRolePermissions("role-a")
	if err != nil {
		t.Error("failed test get role permissions", err)
	}
	if len(rolePermissions) != 2 {
		t.Error("failed test get role permissions", err)
	}
	var r authority.Role
	db.Where("slug = ?", "role-a").First(&r)
	db.Where("role_id = ?", r.ID).Delete(authority.RolePermission{})
	db.Where("slug = ?", "role-a").Delete(authority.Role{})
	db.Where("slug = ?", "permission-a").Delete(authority.Permission{})
	db.Where("slug = ?", "permission-b").Delete(authority.Permission{})
}

func TestTransaction(t *testing.T) {
	auth := authority.New(authority.Options{
		TablesPrefix: "authority_",
		DB:           db,
	})
	authority.Role{
		NA
	}
	tx := auth.BeginTX()
	err := tx.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("failed test transactions", err)
	}

	err = tx.CreatePermission(authority.Permission{
		Name: "Permission A",
		Slug: "permission-a",
	})
	if err != nil {
		t.Error("failed test transactions", err)
	}
	err = tx.CreatePermission(authority.Permission{
		Name: "Permission B",
		Slug: "permission-b",
	})
	if err != nil {
		t.Error("failed test transactions", err)
	}
	tx.Rollback()

	var rCount int64
	db.Model(authority.Role{}).Count(&rCount)
	if rCount != 0 {
		t.Error("failed test transactions")
	}
	var permCount int64
	db.Model(authority.Permission{}).Count(&permCount)
	if permCount != 0 {
		t.Error("failed test transactions")
	}

	tx = auth.BeginTX()
	err = tx.CreateRole(authority.Role{
		Name: "Role A",
		Slug: "role-a",
	})
	if err != nil {
		t.Error("failed test transactions", err)
	}

	err = tx.CreatePermission(authority.Permission{
		Name: "Permission A",
		Slug: "permission-a",
	})
	if err != nil {
		t.Error("failed test transactions", err)
	}
	err = tx.CreatePermission(authority.Permission{
		Name: "Permission B",
		Slug: "permission-b",
	})
	if err != nil {
		t.Error("failed test transactions", err)
	}
	tx.Commit()

	db.Model(authority.Role{}).Count(&rCount)
	if rCount != 1 {
		t.Error("failed test transactions")
	}
	db.Model(authority.Permission{}).Count(&permCount)
	if permCount != 2 {
		t.Error("failed test transactions")
	}

	t.Cleanup(func() {
		db.Where("slug = ?", "role-a").Delete(&authority.Role{})
		db.Where("slug = ?", "permission-a").Delete(&authority.Permission{})
		db.Where("slug = ?", "permission-b").Delete(&authority.Permission{})
	})
}
