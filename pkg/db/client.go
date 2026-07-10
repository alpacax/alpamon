package db

import (
	"fmt"
	"sync"

	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	_ "github.com/glebarez/go-sqlite"
)

type DBClientManager struct {
	client *ent.Client
	once   sync.Once
	path   string
}

func NewDBClientManager(path string) *DBClientManager {
	return &DBClientManager{
		path: path,
	}
}

func sqliteDSN(path string) string {
	return fmt.Sprintf("file:%s?cache=shared&__pragma=foreign_keys(1)", path)
}

func (cm *DBClientManager) GetClient() (*ent.Client, error) {
	var err error
	cm.once.Do(func() {
		cm.client, err = ent.Open("sqlite3", sqliteDSN(cm.path))
	})
	return cm.client, err
}
