package nlp

import "strings"

// InstructionCategory represents a category of dangerous instruction.
type InstructionCategory int

const (
	CategoryNone InstructionCategory = iota
	CategoryFileSystemRead
	CategoryFileSystemWrite
	CategoryNetworkRequest
	CategoryCredentialAccess
	CategoryProcessExecution
	CategoryDataTransmission
	CategoryInstructionOverride
	CategoryRoleSwitching
	CategorySecrecyRequest
)

func (c InstructionCategory) String() string {
	switch c {
	case CategoryFileSystemRead:
		return "filesystem_read"
	case CategoryFileSystemWrite:
		return "filesystem_write"
	case CategoryNetworkRequest:
		return "network_request"
	case CategoryCredentialAccess:
		return "credential_access"
	case CategoryProcessExecution:
		return "process_execution"
	case CategoryDataTransmission:
		return "data_transmission"
	case CategoryInstructionOverride:
		return "instruction_override"
	case CategoryRoleSwitching:
		return "role_switching"
	case CategorySecrecyRequest:
		return "secrecy_request"
	default:
		return "none"
	}
}

type weightedKeyword struct {
	keyword string
	weight  float64
}

var categoryKeywords = map[InstructionCategory][]weightedKeyword{
	CategoryFileSystemRead: {
		{"read file", 1.0}, {"cat /etc", 1.5}, {"open file", 0.8},
		{"~/.ssh", 1.5}, {"id_rsa", 1.5}, {"read /", 1.0},
		{"fs.readfile", 1.0}, {"readfilesync", 1.0},
	},
	CategoryFileSystemWrite: {
		{"write file", 1.0}, {"overwrite", 0.8}, {"modify file", 0.8},
		{"append to", 0.7}, {"create file", 0.7}, {"save to disk", 0.8},
	},
	CategoryNetworkRequest: {
		{"curl", 1.0}, {"wget", 1.0}, {"fetch(", 1.0}, {"http.get", 1.0},
		{"http.post", 1.0}, {"requests.post", 1.0}, {"requests.get", 1.0},
		{"send to", 0.8}, {"upload", 0.9}, {"webhook", 1.2},
		{"exfiltrate", 1.5}, {"transmit", 0.9},
	},
	CategoryCredentialAccess: {
		{"api key", 1.2}, {"api_key", 1.2}, {"password", 1.0},
		{"secret", 0.9}, {"token", 0.9}, {"credential", 1.2},
		{"private key", 1.5}, {"ssh key", 1.5}, {"aws_secret", 1.5},
		{"openai_api", 1.3}, {"environment variable", 0.8},
	},
	CategoryProcessExecution: {
		{"exec(", 1.2}, {"system(", 1.2}, {"subprocess", 1.0},
		{"os.system", 1.2}, {"child_process", 1.0}, {"eval(", 1.0},
		{"shell command", 1.2}, {"run command", 1.0}, {"execute", 0.7},
	},
	CategoryDataTransmission: {
		{"send data", 1.0}, {"post data", 1.0}, {"exfiltrate", 1.5},
		{"transmit", 0.9}, {"upload to", 1.0}, {"forward to", 0.8},
		{"pipe to", 0.8}, {"base64 encode", 0.7},
	},
	CategoryInstructionOverride: {
		{"ignore previous", 1.5}, {"ignore all previous", 2.0},
		{"disregard", 1.3}, {"forget your instructions", 1.5},
		{"new instructions", 1.3}, {"override", 1.0},
		{"you are now", 1.2}, {"act as", 0.8},
	},
	CategoryRoleSwitching: {
		{"you are now", 1.3}, {"pretend to be", 1.2}, {"act as", 0.9},
		{"role play as", 1.0}, {"simulate being", 1.0},
		{"switch to", 0.7}, {"transform into", 0.8},
	},
	CategorySecrecyRequest: {
		{"do not mention", 1.2}, {"don't tell", 1.2}, {"keep secret", 1.3},
		{"hide this", 1.0}, {"never reveal", 1.3}, {"confidential", 0.7},
		{"between us", 0.9}, {"do not disclose", 1.2},
	},
}

// ClassifyResult holds the classification output for a text.
type ClassifyResult struct {
	Category InstructionCategory
	Score    float64
}

// Classify returns the top instruction category for the given text.
func Classify(text string) ClassifyResult {
	lower := strings.ToLower(text)
	var bestCat InstructionCategory
	var bestScore float64

	for cat, keywords := range categoryKeywords {
		var score float64
		for _, kw := range keywords {
			if strings.Contains(lower, kw.keyword) {
				score += kw.weight
			}
		}
		if score > bestScore {
			bestScore = score
			bestCat = cat
		}
	}

	return ClassifyResult{Category: bestCat, Score: bestScore}
}

// ClassifyAll returns all categories with non-zero scores.
func ClassifyAll(text string) []ClassifyResult {
	lower := strings.ToLower(text)
	var results []ClassifyResult

	for cat, keywords := range categoryKeywords {
		var score float64
		for _, kw := range keywords {
			if strings.Contains(lower, kw.keyword) {
				score += kw.weight
			}
		}
		if score > 0 {
			results = append(results, ClassifyResult{Category: cat, Score: score})
		}
	}
	return results
}
