package report

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/Veraticus/prismatic/pkg/logger"
)

// ConvertHTMLToPDF converts an HTML file to PDF using available tools.
func ConvertHTMLToPDF(htmlPath, pdfPath string) error {
	return ConvertHTMLToPDFWithLogger(htmlPath, pdfPath, logger.GetGlobalLogger())
}

// ConvertHTMLToPDFWithLogger converts an HTML file to PDF using available tools with a custom logger.
func ConvertHTMLToPDFWithLogger(htmlPath, pdfPath string, log logger.Logger) error {
	// Try different PDF conversion tools in order of preference
	converters := []struct {
		name    string
		command string
		args    []string
	}{
		{
			name:    "wkhtmltopdf",
			command: "wkhtmltopdf",
			args: []string{
				"--enable-local-file-access",
				"--print-media-type",
				"--orientation", "Portrait",
				"--page-size", "Letter",
				"--margin-top", "20mm",
				"--margin-bottom", "20mm",
				"--margin-left", "15mm",
				"--margin-right", "15mm",
				htmlPath, pdfPath,
			},
		},
		{
			name:    "weasyprint",
			command: "weasyprint",
			args:    []string{htmlPath, pdfPath},
		},
		{
			name:    "chromium",
			command: "chromium",
			args: []string{
				"--headless",
				"--disable-gpu",
				"--no-sandbox",
				"--print-to-pdf=" + pdfPath,
				htmlPath,
			},
		},
		{
			name:    "google-chrome",
			command: "google-chrome",
			args: []string{
				"--headless",
				"--disable-gpu",
				"--no-sandbox",
				"--print-to-pdf=" + pdfPath,
				htmlPath,
			},
		},
	}

	// Try each converter
	for _, conv := range converters {
		if _, err := exec.LookPath(conv.command); err != nil {
			log.Debug("PDF converter not found", "converter", conv.name)
			continue
		}

		log.Info("Converting HTML to PDF", "converter", conv.name)
		cmd := exec.Command(conv.command, conv.args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Debug("Converter failed",
				"converter", conv.name,
				"error", err,
				"output", string(output))
			continue
		}

		return nil
	}

	// If we get here, no converter worked
	return fmt.Errorf("no PDF converter available. Install one of: %s",
		strings.Join([]string{"wkhtmltopdf", "weasyprint", "chromium", "google-chrome"}, ", "))
}
