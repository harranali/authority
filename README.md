# Authority

![Build Status](https://github.com/harranali/authority/actions/workflows/build-main.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/harranali/authority)](https://goreportcard.com/report/github.com/harranali/authority)
[![GoDoc](https://godoc.org/github.com/harranali/authority?status.svg)](https://godoc.org/github.com/harranali/authority)
[![Coverage Status](https://coveralls.io/repos/github/harranali/authority/badge.svg?branch=main)](https://coveralls.io/github/harranali/authority?branch=main)

Role Based Access Control (RBAC) Go package with database persistence 

# Install
First get `authority`
```bash
go get github.com/harranali/authority
```
Next get the database driver for `gorm` that you will be using 
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
err := auth.CreateRole("role-1")

// create permissions
err := auth.CreatePermission("permission-1")
err = auth.CreatePermission("permission-2")
err = auth.CreatePermission("permission-3")

// assign the permissions to the role
err := auth.AssignPermissions("role-1", []string{
    "permission-1",
    "permission-2",
    "permission-3",
})

// assign a role to user (user id) 
err = auth.AssignRole(1, "role-a")

// check if the user have a given role
ok, err := auth.CheckRole(1, "role-a")

// check if a user have a given permission 
ok, err := auth.CheckPermission(1, "permission-d")

// check if a role have a given permission
ok, err := auth.CheckRolePermission("role-a", "permission-a")
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

###  func (a *Authority) CreateRole(roleName string) error
CreateRole stores a role in the database it accepts the role name. it returns an error incase of any
```go
// create role
err := auth.CreateRole("role-1")
```

### func (a *Authority) CreatePermission(permName string) error
CreatePermission stores a permission in the database it accepts the permission name. it returns an error in case of any
```go
// create permissions
err := auth.CreatePermission("permission-1")
err = auth.CreatePermission("permission-2")
err = auth.CreatePermission("permission-3")
```


### func (a *Authority) AssignPermissions(roleName string, permNames []string) error
AssignPermissions assigns a group of permissions to a given role it accepts in the first parameter the role name, it returns an error if there is not  matching record of the role name in the database. the second parameter is a slice of strings which represents a group of permissions to be assigned to the role. if any of these permissions doesn't have a matching record in the database, the operations stops, changes reverted and an error is returned. in case of success nothing is returned
```go
// assign the permissions to the role
err := auth.AssignPermissions("role-1", []string{
    "permission-1",
    "permission-2",
    "permission-3",
})
```


### func (a *Authority) AssignRole(userID uint, roleName string) error
AssignRole assigns a given role to a user. the first parameter is the user id, the second parameter is the role name. if the role name doesn't have a matching record in the data base an error is returned. if the user have already a role assigned to him an error is returned.
```go
// assign a role to user (user id) 
err = auth.AssignRole(1, "role-a")
```


### func (a *Authority) CheckRole(userID uint, roleName string) (bool, error) 
CheckRole checks if a role is assigned to a user. it accepts the user id as the first parameter. the role as the second parameter. it returns an error if the role is not present in database
```go
// check if the user have a given role
ok, err := auth.CheckRole(1, "role-a")
```

### func (a *Authority) CheckPermission(userID uint, permName string) (bool, error)
CheckPermission checks if a permission is assigned to a user. it accepts the user id as the first parameter. the permission as the second parameter. it returns an error if the user donesn't have a rols assigned. it returns an error if the user's role doesn't have the permission assigned. it returns an error if the permission is not present in the database
```go
// check if a user have a given permission 
ok, err := auth.CheckPermission(1, "permission-d")
```

### func (a *Authority) CheckRolePermission(roleName string, permName string) (bool, error)
CheckRolePermission checks if a role has the permission assigned. it accepts the role as the first parameter. it accepts the permission as the second parameter. it returns an error if the role is not present in database. it returns an error if the permission is not present in database
```go
// check if a role have a given permission
ok, err := auth.CheckRolePermission("role-a", "permission-a")
```

### func (a *Authority) RevokeRole(userID uint, roleName string) error
RevokeRole revokes a user's role. it returns a error in case of any
```go
err = auth.RevokeRolePermission("role-a", "permission-a")
```


### func (a *Authority) RevokePermission(userID uint, permName string) error
RevokePermission revokes a permission from the user's assigned role. it returns an error in case of any
```go
err = auth.RevokePermission(1, "permission-a")
```


### func (a *Authority) RevokeRolePermission(roleName string, permName string) error
RevokeRolePermission revokes a permission from a given role  it returns an error in case of any
```go
err = auth.RevokeRolePermission("role-a", "permission-a")
```

### func (a *Authority) GetRoles() ([]string, error)
GetRoles returns all stored roles
```go
roles, err := auth.GetRoles()
```

### func (a *Authority) GetPermissions() ([]string, error)
GetPermissions retuns all stored permissions
```go
permissions, err := auth.GetPermissions()
```

### func (a *Authority) DeleteRole(roleName string) error
DeleteRole deletes a given role. if the role is assigned to a user it returns an error
```go
err := auth.DeleteRole("role-b")
```

### func (a *Authority) DeletePermission(permName string) error 
DeletePermission deletes a given permission. if the permission is assigned to a role it returns an error
```go
err := auth.DeletePermission("permission-c")
```
