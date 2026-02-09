package output

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

var (
	titleColor    = color.New(color.FgWhite, color.Bold)
	labelColor    = color.New(color.FgCyan)
	valueColor    = color.New(color.FgWhite)
	arrowColor    = color.New(color.FgYellow)
	sectionColor  = color.New(color.FgMagenta, color.Bold)
	errorColor    = color.New(color.FgRed)
	dimColor      = color.New(color.FgHiBlack)
	providerColor = color.New(color.FgGreen)
)

type Formatter struct{}

func New() *Formatter {
	return &Formatter{}
}

func (f *Formatter) PrintTitle(domain string) {
	fmt.Println()
	titleColor.Println(domain)
	dimColor.Println(strings.Repeat("━", 50))
}

func (f *Formatter) PrintSection(name string) {
	fmt.Println()
	sectionColor.Println(name)
}

func (f *Formatter) PrintKeyValue(key, value string) {
	labelColor.Printf("%-12s ", key)
	valueColor.Println(value)
}

func (f *Formatter) PrintArrowItem(value string) {
	arrowColor.Print("  → ")
	valueColor.Println(value)
}

func (f *Formatter) PrintArrowItemWithProvider(value, provider string) {
	arrowColor.Print("  → ")
	valueColor.Print(value)
	if provider != "" {
		dimColor.Print(" [")
		providerColor.Print(provider)
		dimColor.Print("]")
	}
	fmt.Println()
}

func (f *Formatter) PrintArrowItemWithProviderAndASN(value, provider, asn string) {
	arrowColor.Print("  → ")
	valueColor.Print(value)
	if provider != "" {
		dimColor.Print(" [")
		providerColor.Print(provider)
		dimColor.Print("]")
	}
	if asn != "" {
		dimColor.Printf(" (%s)", asn)
	}
	fmt.Println()
}

func (f *Formatter) PrintTraceStep(zone, server string) {
	dimColor.Print("  ")
	valueColor.Print(zone)
	dimColor.Print(" → ")
	valueColor.Println(server)
}

func (f *Formatter) PrintRecord(recordType, value string) {
	labelColor.Printf("  %-6s ", recordType)
	valueColor.Println(value)
}

func (f *Formatter) PrintRecordWithProvider(recordType, value, providerName string) {
	labelColor.Printf("  %-6s ", recordType)
	valueColor.Print(value)
	if providerName != "" {
		dimColor.Print(" [")
		providerColor.Print(providerName)
		dimColor.Print("]")
	}
	fmt.Println()
}

func (f *Formatter) PrintRecordWithProviderAndASN(recordType, value, providerName, asn string) {
	labelColor.Printf("  %-6s ", recordType)
	valueColor.Print(value)
	if providerName != "" {
		dimColor.Print(" [")
		providerColor.Print(providerName)
		dimColor.Print("]")
	}
	if asn != "" {
		dimColor.Printf(" (%s)", asn)
	}
	fmt.Println()
}

func (f *Formatter) PrintError(msg string) {
	errorColor.Printf("  ✗ %s\n", msg)
}

func (f *Formatter) PrintDim(msg string) {
	dimColor.Printf("  %s\n", msg)
}

func (f *Formatter) Finish() {
	fmt.Println()
}
