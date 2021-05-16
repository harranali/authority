package authority_test

import (
	"testing"

	"github.com/harranali/authority"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestCreateRole(t *testing.T) {
	dsn := "root:@tcp(127.0.0.1:3306)/db_test?charset=utf8mb4&parseTime=True&loc=Local"
	db, _ := gorm.Open(mysql.Open(dsn), &gorm.Config{})

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
