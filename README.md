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
err := auth.CreatePermissions("permission-1")
err = auth.CreatePermissions("permission-2")
err = auth.CreatePermissions("permission-3")

// assign permissions to role
err := auth.AssignPermissions("role-1", []string{
    "permission-1",
    "permission-2",
    "permission-3",
})

// assign a role to user (user id) 
err = auth.AssignRole(1, "role-a")

```
