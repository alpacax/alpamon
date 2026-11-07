package exposure

// testHookReadStage injects failures at read stages. Tests install it before
// starting any exposure goroutines and remove it only after they finish.
var testHookReadStage func(stage string)

var testHookEncodePanic func() bool

func readHook(stage string) {
	if testHookReadStage != nil {
		testHookReadStage(stage)
	}
}
