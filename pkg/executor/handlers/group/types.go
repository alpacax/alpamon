package group

// GroupData contains data for group operations
type GroupData struct {
	Groupname string `validate:"required"`
	GID       uint64 `validate:"required,min=1"`
}

// DeleteGroupData contains data for group deletion
type DeleteGroupData struct {
	Groupname string `validate:"required"`
}
