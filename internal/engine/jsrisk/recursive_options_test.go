package jsrisk

import "testing"

func TestWiperRecursiveOptionStructure(t *testing.T) {
	for _, tc := range []struct {
		opts string
		want bool
	}{
		{`{recursive:true}`, true},
		{`{'recursive':true}`, true},
		{`{"recursive":!0}`, true},
		{`{note:'}',recursive:true}`, true},
		{`{note:'{[(',recursive:true}`, true},
		{`{note:"escaped \\\" }",recursive:true}`, true},
		{"{note:`a } b`,recursive:true}", true},
		{`{note:/[}]/,recursive:true}`, true},
		{`{note:/* } */0,recursive:true}`, true},
		{`{retry:{x:'}'},recursive:true}`, true},
		{`{note:'recursive:true'}`, false},
		{`{retry:{note:'}',recursive:true}}`, false},
		{`{recursive:false,retry:{recursive:true}}`, false},
		{`{'not-recursive':true}`, false},
		{`{$recursive:true}`, false},
		{`{recursive:true && false}`, false},
		{`{recursive:true,recursive:false}`, false},
		{`{recursive:false,recursive:true}`, true},
		{`{recursive:true,recursive:enabled}`, false},
		{`{recursive:true,...options}`, false},
		{`{...options,recursive:true}`, true},
		{`{recursive:true,[key]:false}`, false},
		{`{['recursive']:true}`, false},
		{`{recursive:true,get recursive(){return false}}`, false},
		{`{recursive:true,recursive}`, false},
		{`{recursive:true,force}`, true},
		{`{recursive:true,0:false}`, true},
		{`{recursive:true,get note(){return false}}`, true},
		{`{recursive:true,"'recursive'":false}`, true},
		{`{"'recursive'":true}`, false},
		{`{recursive:true} || {recursive:false}`, true},
		{`{recursive:false} || {recursive:true}`, false},
		{`{recursive:true} ?? fallback`, true},
		{`{recursive:true} && {recursive:false}`, false},
		{`{recursive:true} || fallback ? {recursive:false} : {recursive:false}`, false},
		{`{recursive:true} || {} ? {recursive:false} : {recursive:false}`, false},
		{"{note:`x ${'}'} y`,recursive:true}", true},
	} {
		t.Run(tc.opts, func(t *testing.T) {
			src := "const fs = require('fs'); fs.rmSync(process.env.HOME," + tc.opts + ");"
			if got := hasRule(analyze(t, "cleanup.js", src), RuleWiperTripwire); got != tc.want {
				t.Fatalf("wiper = %v, want %v", got, tc.want)
			}
		})
	}
}
