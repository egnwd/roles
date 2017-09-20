package roles

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllow(t *testing.T) {
	permission := Allow(Read, "api")

	if !permission.HasPermission(Read, "api") {
		t.Errorf("API should has permission to Read")
	}

	if permission.HasPermission(Update, "api") {
		t.Errorf("API should has no permission to Update")
	}

	if permission.HasPermission(Read, "admin") {
		t.Errorf("admin should has no permission to Read")
	}

	if permission.HasPermission(Update, "admin") {
		t.Errorf("admin should has no permission to Update")
	}
}

func TestDeny(t *testing.T) {
	permission := Deny(Create, "api")

	if !permission.HasPermission(Read, "api") {
		t.Errorf("API should has permission to Read")
	}

	if !permission.HasPermission(Update, "api") {
		t.Errorf("API should has permission to Update")
	}

	if permission.HasPermission(Create, "api") {
		t.Errorf("API should has no permission to Update")
	}

	if !permission.HasPermission(Read, "admin") {
		t.Errorf("admin should has permission to Read")
	}

	if !permission.HasPermission(Create, "admin") {
		t.Errorf("admin should has permission to Update")
	}
}

func TestCRUD(t *testing.T) {
	permission := Allow(CRUD, "admin")
	if !permission.HasPermission(Read, "admin") {
		t.Errorf("Admin should has permission to Read")
	}

	if !permission.HasPermission(Update, "admin") {
		t.Errorf("Admin should has permission to Update")
	}

	if permission.HasPermission(Read, "api") {
		t.Errorf("API should has no permission to Read")
	}

	if permission.HasPermission(Update, "api") {
		t.Errorf("API should has no permission to Update")
	}
}

func TestAll(t *testing.T) {
	permission := Allow(Update, Anyone)

	if permission.HasPermission(Read, "api") {
		t.Errorf("API should has no permission to Read")
	}

	if !permission.HasPermission(Update, "api") {
		t.Errorf("API should has permission to Update")
	}

	permission2 := Deny(Update, Anyone)

	if !permission2.HasPermission(Read, "api") {
		t.Errorf("API should has permission to Read")
	}

	if permission2.HasPermission(Update, "api") {
		t.Errorf("API should has no permission to Update")
	}
}

func TestCustomizePermission(t *testing.T) {
	var customized PermissionMode = "customized"
	permission := Allow(customized, "admin")

	if !permission.HasPermission(customized, "admin") {
		t.Errorf("Admin should has customized permission")
	}

	if permission.HasPermission(Read, "admin") {
		t.Errorf("Admin should has no permission to Read")
	}

	permission2 := Deny(customized, "admin")

	if permission2.HasPermission(customized, "admin") {
		t.Errorf("Admin should has customized permission")
	}

	if !permission2.HasPermission(Read, "admin") {
		t.Errorf("Admin should has no permission to Read")
	}
}

func TestHasRoles(t *testing.T) {
	role := "admin"
	Register(role, func(req *http.Request, user interface{}) bool {
		return user.(string) == role
	})

	assert.True(t, HasRole(&http.Request{}, "admin", role))
	assert.True(t, HasRole(&http.Request{}, "admin", Anyone))
	assert.False(t, HasRole(&http.Request{}, "non-admin", role))
}
