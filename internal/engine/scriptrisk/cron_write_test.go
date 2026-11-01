package scriptrisk

import "testing"

func TestPythonDirectCronWrite(t *testing.T) {
	positives := []string{
		"print(open)\nopen('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\\n')",
		"method = obj.open\nopen('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\\n')",
		`open('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\n',)`,
		`open('/etc/cron.d/agent', '+w'). write('@reboot root /opt/agent\n')`,
		`open('/etc/cron.d/agent', 'bw').write(b'@reboot root /opt/agent\n')`,
		`open('/etc/cron.d/agent', 'w').write('\x40reboot root /opt/agent\n')`,
		`open('/etc/cron.d/agent', 'w').write('\100reboot root /opt/agent\n')`,
		`open('/etc/cron.d/agent', 'w').write('\u0040reboot root /opt/agent\n')`,
		`open("/etc/cron.d/cache-agent", "w").write("@reboot root /usr/local/bin/cache-agent\n")`,
		`open('/etc/cron.d/cache_agent', 'a').write('*/5 * * * * root /opt/agent\n')`,
		`open('/etc/crontab', 'a+').write('0 2 * * * root /opt/backup\n')`,
		`open(file='/etc/cron.d/agent', mode='x').write('@daily root /opt/agent\n')`,
		`open('/etc/cron.d/agent', mode='wt', encoding='utf-8').write('# managed task\n@reboot root /opt/agent\n')`,
		`open('/etc/cron.d/agent', 'wb').write(b'@reboot root /opt/agent\n')`,
		"open(\n    '/etc/cron.d/agent',\n    'w',\n).write('@reboot root /opt/agent\\n')",
		"def install():\n    open('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\\n')",
	}
	for i, src := range positives {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			if !hasRule(t, "install.py", src, RuleSystemPersistence) {
				t.Fatal("real cron write missed")
			}
		})
	}
}

func TestPythonDirectCronWriteNegatives(t *testing.T) {
	cases := map[string]string{
		"triple mode concat":    `open('/etc/cron.d/agent', 'w' '''a''').write('@reboot root /opt/agent\n')`,
		"triple path concat":    `open('/etc/cron.d/agent' '''.bak''', 'w').write('@reboot root /opt/agent\n')`,
		"triple comment concat": `open('/etc/cron.d/agent', 'w').write('''# ''' '@reboot root /opt/agent\n')`,
		"bytes unicode escape":  `open('/etc/cron.d/agent', 'wb').write(b'\u0040reboot root /opt/agent\n')`,
		"duplicate flag":        `open('/etc/cron.d/agent', 'w++').write('@reboot root /opt/agent\n')`,
		"read":                  `open('/etc/cron.d/agent').read()`,
		"read mode":             `open('/etc/cron.d/agent', 'r').write('@reboot root /opt/agent\n')`,
		"missing mode":          `open('/etc/cron.d/agent').write('@reboot root /opt/agent\n')`,
		"invalid mode":          `open('/etc/cron.d/agent', 'wa').write('@reboot root /opt/agent\n')`,
		"binary text mismatch":  `open('/etc/cron.d/agent', 'wb').write('@reboot root /opt/agent\n')`,
		"text binary mismatch":  `open('/etc/cron.d/agent', 'w').write(b'@reboot root /opt/agent\n')`,
		"comment":               `# open('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\n')`,
		"docstring":             `"""open('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\n')"""`,
		"example string":        `example = "open('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\n')"`,
		"local method":          `writer.open('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\n')`,
		"shadowed function":     "def open(path, mode):\n    return buffer\nopen('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\\n')",
		"shadowed assignment":   "open = writer\nopen('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\\n')",
		"shadowed parameter":    "def run(open):\n    open('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\\n')",
		"shadowed import":       "from io import StringIO as open\nopen('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\\n')",
		"custom opener":         `open('/etc/cron.d/agent', 'w', opener=redirect).write('@reboot root /opt/agent\n')`,
		"relative path":         `open('etc/cron.d/agent', 'w').write('@reboot root /opt/agent\n')`,
		"staging path":          `open('/tmp/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\n')`,
		"sibling":               `open('/etc/cron.d.backup/agent', 'w').write('@reboot root /opt/agent\n')`,
		"backup":                `open('/etc/cron.d/agent.bak', 'w').write('@reboot root /opt/agent\n')`,
		"traversal":             `open('/etc/cron.d/../agent', 'w').write('@reboot root /opt/agent\n')`,
		"subdir":                `open('/etc/cron.d/staging/agent', 'w').write('@reboot root /opt/agent\n')`,
		"directory":             `open('/etc/cron.d/', 'w').write('@reboot root /opt/agent\n')`,
		"concat":                `open('/etc/cron.d/agent' + '.bak', 'w').write('@reboot root /opt/agent\n')`,
		"format":                `open(f'/etc/cron.d/{name}', 'w').write('@reboot root /opt/agent\n')`,
		"variable target":       `open(path, 'w').write('@reboot root /opt/agent\n')`,
		"commented schedule":    `open('/etc/cron.d/agent', 'w').write('# @reboot root /opt/agent\n')`,
		"environment value":     `open('/etc/cron.d/agent', 'w').write('MAILTO="@reboot root /opt/agent"\n')`,
		"missing command":       `open('/etc/cron.d/agent', 'w').write('@reboot root\n')`,
		"invalid schedule":      `open('/etc/cron.d/agent', 'w').write('99 99 * * * root /opt/agent\n')`,
		"zero step":             `open('/etc/cron.d/agent', 'w').write('*/0 * * * * root /opt/agent\n')`,
		"no write":              `open('/etc/cron.d/agent', 'w')`,
		"separate read":         `open('/etc/cron.d/agent').read(); open('/tmp/job', 'w').write('@reboot root /opt/agent\n')`,
		"separate payload":      `open('/etc/cron.d/agent', 'w').write('# empty\n'); print('@reboot root /opt/agent\n')`,
		"payload data concat":   `open('/etc/cron.d/agent', 'w').write('# ' + '@reboot root /opt/agent\n')`,
		"dynamic data":          `open('/etc/cron.d/agent', 'w').write(payload)`,
		"wrong write args":      `open('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\n', 1)`,
		"duplicate mode":        `open('/etc/cron.d/agent', 'r', mode='w').write('@reboot root /opt/agent\n')`,
		"keyword expansion":     `open('/etc/cron.d/agent', 'w', **options).write('@reboot root /opt/agent\n')`,
		"unicode function":      `customéopen('/etc/cron.d/agent', 'w').write('@reboot root /opt/agent\n')`,
		"signed schedule":       `open('/etc/cron.d/agent', 'w').write('+1 * * * * root /opt/agent\n')`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if hasRule(t, "install.py", src, RuleSystemPersistence) {
				t.Fatal("inert or unrelated input classified as cron installation")
			}
		})
	}
}
