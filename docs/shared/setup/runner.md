# Setup Library - Runner

This is the document for setup task interface and task runner
shared in package `pkg/lib/common/setup`. These structures provides the
capability for running setup tasks as required.

## Types

### `Task`

`Task` interface defines methods required for a setup task

```go
type Task interface {
	Validate() error
	Run() error
	PrintHelp(io.Writer)
}
```

Function | Signature | Description
---------|-----------|------------
Validate | `Validate() error` | Validates check if a task is completed. If certain requirement of successful state is not met, it returns an error containing message for such requirement. Otherwise returns nil if everything looks good
Run | `Run() error` | Run executes the setup task and returns any fatal error.
PrintHelp | `PrintHelp(io.Writer)` | Prints the help of this setup task into given `io.Writer`

### `Runner`

```go
type Runner struct {
	ConsoleWriter io.Writer
    ErrorWriter   io.Writer
    // un-exported fields omitted
}
```

Filed | Type | Description
------|------|------------
ConsoleWriter | `io.Writer` | The writer for console messages
ErrorWriter | `io.Writer` | The writer for error messages

### Functions

#### Receiver functions for `Runner`

```go
func NewRunner() *Runner
```

`NewRunner` returns a new `Runner` structure

```go
func (r *Runner) AddTask(name string, t Task)
```

`AddTask` adds a task to a runner. The runner will run all task
in the order of which `Runner.AddTask` is called

```go
func (r *Runner) RunAll(force bool) error
```

`RunAll` runs all tasks added to the runner.

The flow with `force=false` calls `Task.Validate()`, return success if
no error returned. Otherwise call `Task.Run()` and execute the task.
After `Task.Run()` return, it calls `Task.Validate()` to check if the task
successfully finished.

The flow with `force=true` omits the first call to `Task.Validate()` and calls
`Task.Run()` regarding less if the task hac been done previously.

```go
func (r *Runner) PrintAllHelp() error
```

`PrintAllHelp` calls `Task.PrintHelp(io.Writer)` of all its registered tasks.
In the order of which they are added with parameter `Runner.ConsoleWriter`

```go
func (r *Runner) Run(taskName string, force bool) error
```

`Run` calls `Task.Run()` for the task added with associated with given name

The flow with `force=false` calls `Task.Validate()`, return success if
no error returned. Otherwise call `Task.Run()` and execute the task.
After `Task.Run()` return, it calls `Task.Validate()` to check if the task
successfully finished.

The flow with `force=true` omits the first call to `Task.Validate()` and calls
`Task.Run()` regarding less if the task hac been done previously.

```go
func (r *Runner) PrintHelp(taskName string) error 
```

`PrintHelp` calls `Task.PrintHelp(io.Writer)` for the task added with given name
with parameter `Runner.ConsoleWriter`
