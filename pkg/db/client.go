package db

import (
	"sync"

	"github.com/alpacax/alpamon/v2/internal/sqlitedsn"
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

func (cm *DBClientManager) GetClient() (*ent.Client, error) {
	var err error
	cm.once.Do(func() {
		cm.client, err = ent.Open("sqlite3", sqlitedsn.For(cm.path))
	})
	return cm.client, err
}
