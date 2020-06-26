package setup

import (
	"io"

	"github.com/pkg/errors"
)

type Task interface {
	Run() error
	Validate() error

	SetName(string, string)
	PrintHelp(io.Writer)
}

type Runner struct {
	ConsoleWriter io.Writer
	ErrorWriter   io.Writer

	tasks map[string]Task
	order []string
}

// If the task called is not added to the runner,
// this error is returned
var ErrTaskNotFound = errors.New("Task not found")

// NewRunner returns a new Runner structure
func NewRunner() *Runner {
	r := Runner{
		tasks: make(map[string]Task),
	}
	return &r
}

// AddTask adds a task to a runner. The runner will run all task
// in the order of which Runner.AddTask is called
func (r *Runner) AddTask(name, envPrefix string, t Task) {
	if _, ok := r.tasks[name]; ok {
		// task exist
		return
	}
	r.order = append(r.order, name)
	r.tasks[name] = t
	t.SetName(name, envPrefix)
}

// RunAll runs all tasks added to the runner.
//
// The flow with force=false calls Task.Validate(), return success if no
// error returned. Otherwise call Task.Run() and execute the task. After
// Task.Run() return, it calls Task.Validate() to check if the task
// successfully finished.
//
// The flow with force=true omits the first call to Task.Validate() and
// calls Task.Run() regarding less if the task hac been done previously.
func (r *Runner) RunAll(force bool) error {
	for _, taskName := range r.order {
		if err := r.Run(taskName, force); err != nil {
			return err
		}
	}
	return nil
}

// PrintAllHelp calls Task.PrintHelp(io.Writer) of all its registered tasks.
// In the order of which they are added with parameter Runner.ConsoleWriter
func (r *Runner) PrintAllHelp() error {
	for taskName := range r.tasks {
		if err := r.PrintHelp(taskName); err != nil {
			return err
		}
	}
	return nil
}

// Run calls Task.Run() for the task added with associated with given name
//
// The flow with force=false calls Task.Validate(), return success if no
// error returned. Otherwise call Task.Run() and execute the task. After
// Task.Run() return, it calls Task.Validate() to check if the task
// successfully finished.
//
// The flow with force=true omits the first call to Task.Validate() and
// calls Task.Run() regarding less if the task hac been done previously.
func (r *Runner) Run(taskName string, force bool) error {
	task, ok := r.tasks[taskName]
	if !ok {
		return ErrTaskNotFound
	}
	if !force {
		printToWriter(r.ConsoleWriter, "", "Validating setup task: "+taskName)
		if err := task.Validate(); err == nil {
			printToWriter(r.ConsoleWriter, "", "Setup task "+taskName+" has been done, skipping...")
			return nil
		}
	}
	printToWriter(r.ConsoleWriter, "", "Running setup task: "+taskName)
	if err := task.Run(); err != nil {
		return errors.Wrap(err, "Failed to run setup task "+taskName)
	}
	if err := task.Validate(); err != nil {
		r.PrintHelp(taskName)
		return errors.Wrap(err, "Failed to validate setup task "+taskName)
	}
	return nil
}

// PrintHelp calls Task.PrintHelp(io.Writer) for the task added with
// given name with parameter Runner.ConsoleWriter
func (r *Runner) PrintHelp(taskName string) error {
	task, ok := r.tasks[taskName]
	if !ok {
		return ErrTaskNotFound
	}
	task.PrintHelp(r.ConsoleWriter)
	return nil
}
