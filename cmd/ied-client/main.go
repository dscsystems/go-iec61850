// Command ied-client is a small command-line IEC 61850 MMS client
// demonstrating the client package: browse, read, write and dataset
// access against a live IED.
//
// Usage:
//
//	ied-client -addr host:port <command> [args]
//
// Commands:
//
//	scan                       identify + list logical devices/nodes
//	browse [LD]                list variables (optionally one device)
//	read   LD/LN.DO.DA -fc MX  read a value
//	write  LD/LN.DO.DA -fc CF -type int32 -value 1
//	dataset LD/LN.DataSet      read a dataset
//	control LD/LN.DO -value on operate a control
//	files [get PATH]           list or download files
//	test                       exercise every server feature (self-test)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:102", "server address host:port")
	fcStr := flag.String("fc", "MX", "functional constraint (ST, MX, CO, SP, CF, DC, ...)")
	typeStr := flag.String("type", "", "value type for write: bool, int32, uint32, float32, string")
	valueStr := flag.String("value", "", "value for write")
	password := flag.String("password", "", "ACSE authentication password")
	timeout := flag.Duration("timeout", 20*time.Second, "overall timeout for the command's operations")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	// The association handshake gets its own short deadline; the command
	// then gets the full -timeout budget, so a slow connect never eats
	// into the operation time.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 8*time.Second)
	var opts []client.Option
	opts = append(opts, client.WithTimeout(6*time.Second))
	if *password != "" {
		opts = append(opts, client.WithPassword(*password))
	}
	c, err := client.Dial(dialCtx, *addr, opts...)
	dialCancel()
	if err != nil {
		fatal("connect: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	switch args[0] {
	case "scan":
		cmdScan(ctx, c)
	case "browse":
		cmdBrowse(ctx, c, args[1:])
	case "read":
		cmdRead(ctx, c, args[1:], *fcStr)
	case "write":
		cmdWrite(ctx, c, args[1:], *fcStr, *typeStr, *valueStr)
	case "dataset":
		cmdDataSet(ctx, c, args[1:])
	case "control":
		cmdControl(ctx, c, args[1:], *typeStr, *valueStr)
	case "files":
		cmdFiles(ctx, c, args[1:])
	case "test":
		// The full exercise manages its own per-step deadlines so it can
		// wait for reports; it ignores the -timeout flag.
		if !cmdTest(c) {
			os.Exit(1)
		}
	default:
		fatal("unknown command %q", args[0])
	}
}

func cmdFiles(ctx context.Context, c *client.Client, args []string) {
	if len(args) >= 2 && args[0] == "get" {
		data, err := c.ReadFile(ctx, args[1])
		if err != nil {
			fatal("read file %s: %v", args[1], err)
		}
		os.Stdout.Write(data)
		return
	}
	dir := ""
	if len(args) > 0 {
		dir = args[0]
	}
	entries, err := c.FileDirectory(ctx, dir)
	if err != nil {
		fatal("file directory: %v", err)
	}
	for _, e := range entries {
		fmt.Printf("%10d  %s  %s\n", e.Size, e.LastModified.Format("2006-01-02 15:04"), e.Name)
	}
}

func cmdControl(ctx context.Context, c *client.Client, args []string, typeStr, valueStr string) {
	if len(args) == 0 {
		fatal("control requires a controllable object reference, e.g. LD/LN.SPCSO1")
	}
	if typeStr == "" {
		typeStr = "bool"
	}
	v, err := parseValue(typeStr, valueStr)
	if err != nil {
		fatal("%v", err)
	}
	co, err := c.ControlFor(ctx, model.ObjectReference(args[0]))
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("control model: %s\n", co.Model())
	if err := co.Operate(ctx, v, client.WithOriginator(model.OrCatStationControl, "ied-client")); err != nil {
		fatal("operate: %v", err)
	}
	fmt.Printf("operated %s = %s\n", args[0], v)
}

func cmdScan(ctx context.Context, c *client.Client) {
	vendor, model, rev, err := c.MMS().Identify(ctx)
	if err != nil {
		fmt.Println("identify: (not supported)", err)
	} else {
		fmt.Printf("Vendor:   %s\nModel:    %s\nRevision: %s\n", vendor, model, rev)
	}
	lds, err := c.LogicalDevices(ctx)
	if err != nil {
		fatal("logical devices: %v", err)
	}
	fmt.Printf("\nLogical devices (%d):\n", len(lds))
	for _, ld := range lds {
		lns, _ := c.LogicalNodes(ctx, ld)
		fmt.Printf("  %s  (%d logical nodes: %v)\n", ld, len(lns), lns)
	}
}

func cmdBrowse(ctx context.Context, c *client.Client, args []string) {
	lds, err := c.LogicalDevices(ctx)
	if err != nil {
		fatal("logical devices: %v", err)
	}
	if len(args) > 0 {
		lds = []string{args[0]}
	}
	for _, ld := range lds {
		names, err := c.MMS().GetNameList(ctx, mms.ClassNamedVariable, ld)
		if err != nil {
			fatal("browse %s: %v", ld, err)
		}
		fmt.Printf("%s (%d variables):\n", ld, len(names))
		for _, n := range names {
			fmt.Printf("  %s\n", n)
		}
	}
}

func cmdRead(ctx context.Context, c *client.Client, args []string, fcStr string) {
	if len(args) == 0 {
		fatal("read requires an object reference")
	}
	fc, err := model.ParseFC(fcStr)
	if err != nil {
		fatal("%v", err)
	}
	ref := model.ObjectReference(args[0])
	v, err := c.Read(ctx, ref, fc)
	if err != nil {
		fatal("read %s [%s]: %v", ref, fc, err)
	}
	fmt.Printf("%s [%s] = %s  (%s)\n", ref, fc, v, v.Type())
}

func cmdWrite(ctx context.Context, c *client.Client, args []string, fcStr, typeStr, valueStr string) {
	if len(args) == 0 {
		fatal("write requires an object reference")
	}
	fc, err := model.ParseFC(fcStr)
	if err != nil {
		fatal("%v", err)
	}
	v, err := parseValue(typeStr, valueStr)
	if err != nil {
		fatal("%v", err)
	}
	ref := model.ObjectReference(args[0])
	if err := c.Write(ctx, ref, fc, v); err != nil {
		fatal("write %s [%s]: %v", ref, fc, err)
	}
	fmt.Printf("wrote %s [%s] = %s\n", ref, fc, v)
}

func cmdDataSet(ctx context.Context, c *client.Client, args []string) {
	if len(args) == 0 {
		fatal("dataset requires a reference LD/LN.DataSet")
	}
	ds, err := c.ReadDataSet(ctx, model.ObjectReference(args[0]))
	if err != nil {
		fatal("read dataset: %v", err)
	}
	fmt.Printf("%s (%d members):\n", ds.Ref, len(ds.Members))
	for _, m := range ds.Members {
		fmt.Printf("  %s [%s] = %s\n", m.Ref, m.FC, m.Value)
	}
}

func parseValue(typeStr, valueStr string) (*mms.Value, error) {
	switch typeStr {
	case "bool":
		b, err := strconv.ParseBool(valueStr)
		return mms.NewBool(b), err
	case "int32":
		n, err := strconv.ParseInt(valueStr, 10, 32)
		return mms.NewInt32(int32(n)), err
	case "uint32":
		n, err := strconv.ParseUint(valueStr, 10, 32)
		return mms.NewUint32(uint32(n)), err
	case "float32":
		f, err := strconv.ParseFloat(valueStr, 32)
		return mms.NewFloat32(float32(f)), err
	case "string":
		return mms.NewVisibleString(valueStr), nil
	default:
		return nil, fmt.Errorf("unknown -type %q (want bool, int32, uint32, float32, string)", typeStr)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ied-client: "+format+"\n", args...)
	os.Exit(1)
}
