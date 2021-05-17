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

	db, _ = gorm.Open(mysql.Open(dsn), &gorm.Config{})

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

	// assert
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

	// assert
	var r authority.Role
	db.Where("name = ?", "role-a").First(&r)
	var userRoles int64
	db.Model(authority.UserRole{}).Where("role_id = ?", r.ID).Count(&userRoles)
	if userRoles != 1 {
		t.Error("failed assigning roles to permission")
	}

	// clean up
	db.Where("role_id = ?", r.ID).Delete(authority.UserRole{})
	db.Where("name = ?", "role-a").Delete(authority.Role{})
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

	// assign the role
	err = auth.AssignRole(1, "role-a")
	if err != nil {
		t.Error("unexpected error while assigning role.", err)
	}

	// test
	ok, err := auth.CheckPermission(1, "permission-a")
	if err != nil {
		t.Error("unexpected error while checking permission of a user.", err)
	}
	if !ok {
		t.Error("failed to assert checking permission of a user")
	}

	//clean up
	var r authority.Role
	db.Where("name = ?", "role-a").First(&r)
	db.Where("role_id = ?", r.ID).Delete(authority.UserRole{})
	db.Where("role_id = ?", r.ID).Delete(authority.RolePermission{})
	db.Where("name = ?", "permission-a").Delete(authority.Permission{})
	db.Where("name = ?", "permission-b").Delete(authority.Permission{})
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

	//clean up
	var r authority.Role
	db.Where("name = ?", "role-a").First(&r)
	db.Where("role_id = ?", r.ID).Delete(authority.RolePermission{})
	db.Where("name = ?", "permission-a").Delete(authority.Permission{})
	db.Where("name = ?", "permission-b").Delete(authority.Permission{})
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

	// test
	err = auth.RevokePermission(1, "permission-a")
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

	// test
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
