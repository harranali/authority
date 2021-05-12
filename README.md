# Authority (Under Development)
Role Based Access Control (RBAC) Go package with database persistence 

# Install
```bash
go get github.com/harranali/authority
```

# Usage
To initiate `authority` you need to pass two variables the first one is the the database table names prefix, the second is an instance of [gorm](https://github.com/go-gorm/gorm)
```go
dsn := "dbuser:dbpassword@tcp(127.0.0.1:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local"
db, _ := gorm.Open(mysql.Open(dsn), &gorm.Config{})

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

#### func New(opts Options) *Authority
New initates authority
```go
dsn := "dbuser:dbpassword@tcp(127.0.0.1:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local"
db, _ := gorm.Open(mysql.Open(dsn), &gorm.Config{})

auth := authority.New(authority.Options{
    TablesPrefix: "authority_",
    DB:           db,
})
```

#### func Resolve() *Authority
Resolve returns the initiated instance
```go
auth := authority.Resolve()
```

####  func (a *Authority) CreateRole(roleName string) error
CreateRole stores a role in the database it accepts the role name. it returns an error incase of any
```go
// create role
err := auth.CreateRole("role-1")
```

#### func (a *Authority) CreatePermission(permName string) error
CreatePermission stores a permission in the database it accepts the permission name. it returns an error in case of any
```go
// create permissions
err := auth.CreatePermission("permission-1")
err = auth.CreatePermission("permission-2")
err = auth.CreatePermission("permission-3")
```


#### func (a *Authority) AssignPermissions(roleName string, permNames []string) error
AssignPermissions assigns a group of permissions to a given role it accepts in the first parameter the role name, it returns an error if there is not  matching record of the role name in the database. the second parameter is a slice of strings which represents a group of permissions to be assigned to the role. if any of these permissions doesn't have a matching record in the database, the operations stops, changes reverted and an error is returned. in case of success nothing is returned
```go
// assign the permissions to the role
err := auth.AssignPermissions("role-1", []string{
    "permission-1",
    "permission-2",
    "permission-3",
})
```


#### func (a *Authority) AssignRole(userID uint, roleName string) error
AssignRole assigns a given role to a user. the first parameter is the user id, the second parameter is the role name. if the role name doesn't have a matching record in the data base an error is returned. if the user have already a role assigned to him an error is returned.
```go
// assign a role to user (user id) 
err = auth.AssignRole(1, "role-a")
```


#### func (a *Authority) CheckRole(userID uint, roleName string) (bool, error) 
CheckRole checks if a role is assigned to a user. it accepts the user id as the first parameter. the role as the second parameter. it returns an error if the role is not present in database
```go
// check if the user have a given role
ok, err := auth.CheckRole(1, "role-a")
```

#### func (a *Authority) CheckPermission(userID uint, permName string) (bool, error)
CheckPermission checks if a permission is assigned to a user. it accepts the user id as the first parameter. the permission as the second parameter. it returns an error if the user donesn't have a rols assigned. it returns an error if the user's role doesn't have the permission assigned. it returns an error if the permission is not present in the database
```go
// check if a user have a given permission 
ok, err := auth.CheckPermission(1, "permission-d")
```

#### func (a *Authority) CheckRolePermission(roleName string, permName string) (bool, error)
CheckRolePermission checks if a role has the permission assigned. it accepts the role as the first parameter. it accepts the permission as the second parameter. it returns an error if the role is not present in database. it returns an error if the permission is not present in database
```go
// check if a role have a given permission
ok, err := auth.CheckRolePermission("role-a", "permission-a")
```
