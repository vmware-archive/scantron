package commands

type AuditCommand struct {
	Database string `long:"database" description:"path to report database" value-name:"PATH" default:"./database.db"`
	Manifest string `long:"manifest" description:"path to manifest" value-name:"PATH"`
}

func (command *AuditCommand) Execute(args []string) error {
	return nil
}
