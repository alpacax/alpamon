package user

// UserData contains data for user operations
type UserData struct {
	Username                string   `validate:"required"`
	UID                     uint64   `validate:"required"`
	GID                     uint64   `validate:"required"`
	Comment                 string   `validate:"required"`
	HomeDirectory           string   `validate:"required"`
	HomeDirectoryPermission string   `validate:"omitempty"`
	Shell                   string   `validate:"required"`
	Groupname               string   `validate:"required"`
	Groups                  []uint64 `validate:"omitempty"`
}

// DeleteUserData contains data for user deletion
type DeleteUserData struct {
	Username           string `validate:"required"`
	PurgeHomeDirectory bool   `validate:"omitempty"`
}

// ModUserData contains data for modifying user
type ModUserData struct {
	Username   string   `validate:"required"`
	Groupnames []string `validate:"required"`
	Comment    string   `validate:"required"`
}
