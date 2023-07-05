# Authority

![Build Status](https://github.com/harranali/authority/actions/workflows/build-main.yml/badge.svg)
![Test Status](https://github.com/harranali/authority/actions/workflows/test-main.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/harranali/authority)](https://goreportcard.com/report/github.com/harranali/authority)
[![GoDoc](https://godoc.org/github.com/harranali/authority?status.svg)](https://godoc.org/github.com/harranali/authority)
[![Coverage Status](https://coveralls.io/repos/github/harranali/authority/badge.svg?branch=main)](https://coveralls.io/github/harranali/authority?branch=main&cache=false)

Role Based Access Control (RBAC) Go package with database persistence 
# Features
- Create Roles
- Create Permissions
- Assign Permissions to Roles
- Supports Assigning Multiple Roles to Users
- Check if a user have a given roles
- Check if a user have a given permission
- Check if a role have a given permission
- Revoke User's Roles
- Revoke Role's permissions
- List all roles assigned to a given user
- List all roles in the database
- List all Permissions in the database
- Delete a given role
- Delete a given ermissions

# Install
1. Go get the package
```bash
go get github.com/harranali/authority
```
2. `Authority` uses the `orm` [gorm](https://gorm.io) to communicate with the database. [gorm](https://gorm.io) needs a database driver in order to work properly. you can install the database driver by runnig a command from the list below, for example if you are using `mysql` database, simply run `go get gorm.io/driver/mysql` and so.
```bash
# mysql 
go get gorm.io/driver/mysql 
# or postgres
go get gorm.io/driver/postgres
# or sqlite
go get gorm.io/driver/sqlite
# or sqlserver
go get gorm.io/driver/sqlserver
# or clickhouse
go get gorm.io/driver/clickhouse
```

# Usage
To initiate `authority` you need to pass two variables the first one is the the database table names prefix, the second is an instance of [gorm](https://github.com/go-gorm/gorm)
```go
// initiate the database (using mysql)
dsn := "dbuser:dbpassword@tcp(127.0.0.1:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local"
db, _ := gorm.Open(mysql.Open(dsn), &gorm.Config{})

// initiate authority
auth := authority.New(authority.Options{
    TablesPrefix: "authority_",
    DB:           db,
})

// create role
err = auth.CreateRole(authority.Role{
	Name: "Role 1",
	Slug: "role-1",
})

// create permissions
err = auth.CreatePermission(authority.Permission{
	Name: "Permission 1",
	Slug: "permission-1",
})
err = auth.CreatePermission(authority.Permission{
	Name: "Permission 2",
	Slug: "permission-2",
})
err = auth.CreatePermission(authority.Permission{
	Name: "Permission 3",
	Slug: "permission-3",
})

// assign the permissions to the role
err = auth.AssignPermissionsToRole("role-1", []string{
	"permission-1",
	"permission-2",
	"permission-3",
})

// assign a role to user (user id = 1)
err = auth.AssignRoleToUser(1, "role-1")

// check if the user have a given role
ok, err := auth.CheckUserRole(1, "role-a")
if ok {
	fmt.Println("yes, user has the role assigned")
}

// check if a user have a given permission
ok, err = auth.CheckUserPermission(1, "permission-d")
if ok {
	fmt.Println("yes, user has the permission assigned")
}

// check if a role have a given permission
ok, err = auth.CheckRolePermission("role-a", "permission-a")
if ok {
	fmt.Println("yes, role has the permission assigned")
}
```

# Docs
### func New(opts Options) *Authority
New initiates authority
```go
dsn := "dbuser:dbpassword@tcp(127.0.0.1:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local"
db, _ := gorm.Open(mysql.Open(dsn), &gorm.Config{})

auth := authority.New(authority.Options{
    TablesPrefix: "authority_",
    DB:           db,
})
```

### func Resolve() *Authority
Resolve returns the initiated instance
```go
auth := authority.Resolve()
```

###  func (a *Authority) CreateRole(r authority.Role) error
Add a new role to the database
it accepts the Role struct as a parameter
it returns an error in case of any
it returns an error if the role is already exists

```go
// create role
err = auth.CreateRole(authority.Role{
	Name: "Role 1",
	Slug: "role-1",
})
```

### func (a *Authority) CreatePermission(p authority.Permission) error
Add a new permission to the database
it accepts the Permission struct as a parameter
it returns an error in case of any
it returns an error if the permission is already exists
```go
// create a permission
err = auth.CreatePermission(authority.Permission{
	Name: "Permission 1",
	Slug: "permission-1",
})
```


### func (a *Authority) AssignPermissionsToRole(roleSlug string, permSlugs []string) error
Assigns a group of permissions to a given role
it accepts the the role slug as the first parameter
the second parameter is a slice of permission slugs (strings) to be assigned to the role
it returns an error in case of any
it returns an error in case the role does not exists
it returns an error in case any of the permissions does not exists
it returns an error in case any of the permissions is already assigned
```go
// assign the permissions to the role
err := auth.AssignPermissions("role-1", []string{
    "permission-1",
    "permission-2",
    "permission-3",
})
```


### func (a *Authority) AssignRoleToUser(userID interface{}, roleSlug string) error
Assigns a role to a given user
it accepts the user id as the first parameter
the second parameter the role slug
it returns an error in case of any
it returns an error in case the role does not exists
it returns an error in case the role is already assigned
```go
// assign a role to user (user id) 
err = auth.AssignRoleToUser(1, "role-a")
```


### func (a *Authority) CheckUserRole(userID interface{}, roleSlug string) (bool, error) 
Checks if a role is assigned to a user
it accepts the user id as the first parameter
the second parameter the role slug
it returns two parameters
the first parameter of the return is a boolean represents whether the role is assigned or not
the second is an error in case of any
in case the role does not exists, an error is returned
```go
// check if the user have a given role
ok, err := auth.CheckUserRole(1, "role-a")
```

### func (a *Authority) CheckUserPermission(userID interface{}, permSlug string) (bool, error)
Checks if a permission is assigned to a user
it accepts in the user id as the first parameter
the second parameter the role slug
it returns two parameters
the first parameter of the return is a boolean represents whether the role is assigned or not
the second is an error in case of any
in case the role does not exists, an error is returned
```go
// check if a user have a given permission 
ok, err := auth.CheckUserPermission(1, "permission-d")
```

### func (a *Authority) CheckRolePermission(roleSlug string, permSlug string) (bool, error)
Checks if a permission is assigned to a role
it accepts in the role slug as the first parameter
the second parameter the permission slug
it returns two parameters
the first parameter of the return is a boolean represents whether the permission is assigned or not
the second is an error in case of any
in case the role does not exists, an error is returned
in case the permission does not exists, an error is returned
```go
// check if a role have a given permission
ok, err := auth.CheckRolePermission("role-a", "permission-a")
```

### func (a *Authority) RevokeUserRole(userID interface{}, roleSlug string) error 
Revokes a user's role
it returns a error in case of any
in case the role does not exists, an error is returned
```go
err = auth.RevokeUserRole(1, "role-a")
```

### func (a *Authority) RevokeRolePermission(roleSlug string, permSlug string) error 
Revokes a roles's permission
it returns a error in case of any
in case the role does not exists, an error is returned
in case the permission does not exists, an error is returned
```go
err = auth.RevokeRolePermission("role-a", "permission-a")
```

### func (a *Authority) GetAllRoles() ([]Role, error)
Returns all stored roles
it returns an error in case of any
```go
roles, err := auth.GetAllRoles()
```

### func (a *Authority) GetUserRoles(userID interface{}) ([]Role, error) 
Returns all user assigned roles
it returns an error in case of any
```go
roles, err := auth.GetUserRoles(1)
```

### func (a *Authority) GetRolePermissions(roleSlug string) ([]Permission, error) 
Returns all role assigned permissions
it returns an error in case of any
```go
permissions, err := auth.GetRolePermissions("role-a")
```

### func (a *Authority) GetAllPermissions() ([]Permission, error)
Returns all stored permissions
it returns an error in case of any
```go
permissions, err := auth.GetAllPermissions()
```

### func (a *Authority) DeleteRole(roleSlug string) error 
Deletes a given role even if it's has assigned permissions
it first deassign the permissions and then proceed with deleting the role
it accepts the role slug as a parameter
it returns an error in case of any
if the role is assigned to a user it returns an error
```go
err := auth.DeleteRole("role-b")
```

### func (a *Authority) DeletePermission(permSlug string) error
Deletes a given permission
it accepts the permission slug as a parameter
it returns an error in case of any
if the permission is assigned to a role it returns an error
```go
err := auth.DeletePermission("permission-c")
```

### Transactions
`authority` supports database transactions by implementing 3 methods `BeginTX()`, `Rollback()`, and `Commit()`
here is an example of how to use transactions
```go

// begin a trnasaction session
tx := auth.BeginTX()
// create role
err = tx.CreateRole(authority.Role{
	Name: "Role 1",
	Slug: "role-1",
})
if err != nil {
    tx.Rollback() // transaction rollback incase of error
    fmt.Println("error creating role", err)
}

// create permissions
err = tx.CreatePermission(authority.Permission{
	Name: "Permission 1",
	Slug: "permission-1",
})
if err != nil {
    tx.Rollback() // transaction rollback incase of error
    fmt.Println("error creating permission", err)
}

// assign the permissions to the role
err = tx.AssignPermissionsToRole("role-1", []string{
	"permission-1",
	"permission-2",
	"permission-3",
})

if err != nil {
    tx.Rollback() // transaction rollback incase of error
    fmt.Println("error assigning permission to role", err)
}
// assign a role to user (user id = 1)
err = tx.AssignRoleToUser(1, "role-1")
if err != nil {
    tx.Rollback() // transaction rollback incase of error
    fmt.Println("error assigning role to user", err)
}

// commit the operations to the database
tx.Commit()
```