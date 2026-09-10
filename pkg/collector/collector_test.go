package collector

import (
	"context"
	"testing"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/collector/check"
	"github.com/alpacax/alpamon/v2/pkg/collector/check/base"
	"github.com/alpacax/alpamon/v2/pkg/collector/scheduler"
	"github.com/alpacax/alpamon/v2/pkg/db/ent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCheckStrategy is a minimal base.CheckStrategy used to verify which
// entries a fake CheckFactory produced tasks for.
type fakeCheckStrategy struct {
	name string
}

func (f *fakeCheckStrategy) Execute(_ context.Context) error { return nil }
func (f *fakeCheckStrategy) GetInterval() time.Duration      { return time.Second }
func (f *fakeCheckStrategy) GetName() string                 { return f.name }
func (f *fakeCheckStrategy) GetBuffer() *base.CheckBuffer    { return nil }
func (f *fakeCheckStrategy) GetClient() *ent.Client          { return nil }

// stubCheckFactory succeeds only for the check types listed in `known` and
// returns check.CreateCheck's real "unknown check type" style error for
// everything else, mirroring DefaultCheckFactory's behavior without pulling
// in every real check implementation.
type stubCheckFactory struct {
	known map[base.CheckType]bool
}

func (f *stubCheckFactory) CreateCheck(args *base.CheckArgs) (base.CheckStrategy, error) {
	if f.known[args.Type] {
		return &fakeCheckStrategy{name: args.Name}, nil
	}
	return nil, &unknownCheckTypeError{checkType: args.Type}
}

type unknownCheckTypeError struct {
	checkType base.CheckType
}

func (e *unknownCheckTypeError) Error() string {
	return "unknown check type: " + string(e.checkType)
}

func newTestCollector() *Collector {
	return &Collector{
		scheduler: scheduler.NewScheduler(),
		buffer:    base.NewCheckBuffer(10),
	}
}

func TestInitTasks_SkipsUnknownCheckType(t *testing.T) {
	c := newTestCollector()
	factory := &stubCheckFactory{known: map[base.CheckType]bool{
		base.CPU: true,
		base.Mem: true,
	}}

	args := collectorArgs{
		conf: []collectConf{
			{Type: base.CPU, Interval: 5},
			{Type: base.CheckType("not-a-real-check"), Interval: 5},
			{Type: base.Mem, Interval: 5},
		},
		checkFactory: factory,
	}

	err := c.initTasks(args)
	require.NoError(t, err)
	assert.Equal(t, 2, c.scheduler.TaskCount())
}

func TestInitTasks_AllUnknownReturnsError(t *testing.T) {
	c := newTestCollector()
	factory := &stubCheckFactory{known: map[base.CheckType]bool{}}

	args := collectorArgs{
		conf: []collectConf{
			{Type: base.CheckType("not-a-real-check"), Interval: 5},
			{Type: base.CheckType("also-not-real"), Interval: 5},
		},
		checkFactory: factory,
	}

	err := c.initTasks(args)
	require.Error(t, err)
	assert.ErrorContains(t, err, "no usable checks")
	assert.Equal(t, 0, c.scheduler.TaskCount())
}

func TestInitTasks_EmptyConfigIsNotAnError(t *testing.T) {
	c := newTestCollector()
	factory := &stubCheckFactory{known: map[base.CheckType]bool{}}

	err := c.initTasks(collectorArgs{conf: nil, checkFactory: factory})
	require.NoError(t, err)
	assert.Equal(t, 0, c.scheduler.TaskCount())
}

// Ensure the real factory used in production also exposes the "unknown
// check type" behavior initTasks relies on, in case check.DefaultCheckFactory
// changes shape.
func TestDefaultCheckFactory_ReturnsErrorForUnknownType(t *testing.T) {
	factory := &check.DefaultCheckFactory{}
	_, err := factory.CreateCheck(&base.CheckArgs{Type: base.CheckType("not-a-real-check")})
	assert.Error(t, err)
}
