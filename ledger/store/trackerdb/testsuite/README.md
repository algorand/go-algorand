!! **DO NOT IMPORT THIS MODULE** !!

---

This is the `generickv` tests implemented _outside_ the package.
This is done to avoid cirucular dependencies on some of the testing wizardry taking place.
Namely, making the tests polymorphic on each database implementation,
so we can reuse the test suite against multiple backends.

# Adding tests to the suite

1. Use the following signature on your tests:

```go
func CustomTestDoingSomething(t *customT) {
    // your test..
}
```

The `customT` type behaves just like `testing.T` but has some extras.

2. Register your test with the suite in the `init()` function in your test file.

```go
func init() {
	// register tests that will run on each KV implementation
	registerTest("something", CustomTestDoingSomething)
}
```