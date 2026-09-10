const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {before, after, test} = require('node:test');
const {chromium} = require('playwright');

const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const payload = '<img src="https://invalid.example/probe" onerror="window.executed=true"><svg onload="window.executed=true"></svg>';
let browser;

before(async () => { browser = await chromium.launch({headless: true}); });
after(async () => { await browser?.close(); });

async function withPage(run) {
    const page = await browser.newPage();
    const requests = [];
    try {
        // Exercise the shipped page at its JSON boundary; no engine mock changes
        // the renderer. Network is intercepted to make injected requests observable.
        await page.route('**/*', route => {
            const url = new URL(route.request().url());
            if (url.href === 'http://aguara.test/') {
                return route.fulfill({contentType: 'text/html', body: html});
            }
            if (url.href === 'http://aguara.test/wasm_exec.js') {
                return route.fulfill({contentType: 'application/javascript', body: 'window.Go = class { importObject = {}; run() {} };'});
            }
            requests.push(url.href);
            return route.abort();
        });
        await page.addInitScript(() => {
            WebAssembly.instantiateStreaming = async () => ({instance: {}});
            window.fetch = async () => ({});
            window.aguaraListRules = () => '[]';
            window.aguaraExplainRule = () => JSON.stringify({id: 'TEST_001'});
            window.aguaraScanContent = async (...args) => {
                window.scanArgs = args;
                if (window.scanError) throw new Error(window.scanError);
                return JSON.stringify(window.scanResult || {findings: [], rules_loaded: 3});
            };
        });
        await page.goto('http://aguara.test/');
        await page.waitForFunction(() => !document.getElementById('scan').disabled);
        await run(page);
        assert.equal(await page.evaluate(() => window.executed === true), false);
        assert.equal(await page.locator('#results img, #results svg, #rule-list img, #rule-list svg').count(), 0);
        assert.deepEqual(requests, []);
    } finally {
        await page.close();
    }
}

async function scan(page, result) {
    await page.evaluate(value => { window.scanResult = value; }, result);
    await page.locator('#content').fill('Sample content');
    await page.locator('#scan').click();
    await page.waitForFunction(() => !document.getElementById('results').textContent.includes('Scanning...'));
}

function finding(overrides = {}) {
    return {rule_id: 'TEST_001', rule_name: 'Test finding', severity: 3, line: 7,
        category: 'prompt-injection', matched_text: 'sample', ...overrides};
}

for (const field of ['rule_id', 'rule_name', 'category', 'line', 'matched_text', 'remediation']) {
    test(`${field} is rendered as literal text`, async () => {
        await withPage(async page => {
            await scan(page, {findings: [finding({[field]: payload})], rules_loaded: 3});
            const expected = field === 'matched_text' ? payload.slice(0, 120) : payload;
            assert.ok((await page.locator('#results').innerText()).includes(expected));
        });
    });
}

test('rule totals are text in both findings and clean output', async () => {
    await withPage(async page => {
        for (const findings of [[finding()], []]) {
            await scan(page, {findings, rules_loaded: payload});
            assert.ok((await page.locator('#results').innerText()).includes(payload));
        }
    });
});

test('scan and catalog errors cannot insert markup', async () => {
    await withPage(async page => {
        await page.evaluate(value => { window.scanError = value; }, payload);
        await scan(page, {});
        assert.equal(await page.locator('#results .error').textContent(), 'Error: ' + payload);
        await page.evaluate(value => {
            window.aguaraListRules = () => { throw new Error(value); };
            loadRuleList();
        }, payload);
        assert.equal(await page.locator('#rule-list .error').textContent(), payload);
    });
});

test('ordinary findings keep severity order, metadata, remediation and preview', async () => {
    await withPage(async page => {
        const match = '&<>"'.repeat(50);
        await scan(page, {findings: [finding({severity: 1}), finding({severity: 4, matched_text: match, remediation: 'Review permissions.'})], rules_loaded: 3});
        assert.deepEqual(await page.locator('.finding').evaluateAll(nodes => nodes.map(n => n.className)), ['finding critical', 'finding low']);
        assert.equal(await page.locator('.finding').first().locator('.finding-meta').first().textContent(), 'CRITICAL - Line 7 - prompt-injection');
        assert.equal(await page.locator('.finding-remediation').textContent(), 'Review permissions.');
        assert.equal(await page.locator('code').first().textContent(), match.slice(0, 120));
        assert.match(await page.locator('.stats').first().textContent(), /^2 findings - 3 rules - /);
    });
});

test('unknown severity falls back to info without creating attributes', async () => {
    await withPage(async page => {
        await scan(page, {findings: [finding({severity: payload})], rules_loaded: 3});
        assert.equal(await page.locator('.finding').getAttribute('class'), 'finding info');
    });
});

test('all severity styles and absent optional values are preserved', async () => {
    await withPage(async page => {
        await scan(page, {findings: [0, 1, 2, 3, 4].map(severity => finding({severity, matched_text: null})), rules_loaded: 3});
        assert.deepEqual(await page.locator('.finding').evaluateAll(nodes => nodes.map(n => n.className)),
            ['finding critical', 'finding high', 'finding medium', 'finding low', 'finding info']);
        assert.equal(await page.locator('.finding-remediation').count(), 0);
        assert.deepEqual(await page.locator('code').allTextContents(), ['', '', '', '', '']);
    });
});

test('clean output, options, tab switching and explain still work', async () => {
    await withPage(async page => {
        await page.locator('#filename').fill('config.json');
        await page.locator('#severity').selectOption('high');
        await page.locator('#profile').selectOption('minimal');
        await scan(page, {findings: [], rules_loaded: 3});
        assert.match(await page.locator('.clean').textContent(), /^No security issues found\. \(3 rules, /);
        assert.deepEqual(await page.evaluate(() => window.scanArgs), ['Sample content', 'config.json', {minSeverity: 'high', profile: 'minimal'}]);
        await page.locator('[data-tab="rules"]').click();
        assert.ok(await page.locator('#tab-rules').isVisible());
        await page.evaluate(value => {
            window.aguaraExplainRule = () => JSON.stringify({name: value});
        }, payload);
        await page.locator('#rule-id').fill('TEST_001');
        await page.locator('#rule-id').press('Enter');
        assert.deepEqual(JSON.parse(await page.locator('#rule-detail').textContent()), {name: payload});
        await page.evaluate(value => {
            window.aguaraExplainRule = () => { throw new Error(value); };
        }, payload);
        await page.locator('#explain-btn').click();
        assert.equal(await page.locator('#rule-detail').textContent(), 'Error: ' + payload);
    });
});

test('real WASM scans and explains results without interpreting document HTML', {
    skip: !process.env.AGUARA_WASM,
    timeout: 60000,
}, async () => {
    assert.ok(process.env.AGUARA_WASM_EXEC, 'AGUARA_WASM_EXEC must match the WASM Go toolchain');
    const page = await browser.newPage();
    const requests = [];
    const errors = [];
    try {
        page.on('pageerror', error => errors.push(error.message));
        const assets = new Map([
            ['http://localhost/', ['text/html', html]],
            ['http://localhost/wasm_exec.js', ['application/javascript', fs.readFileSync(process.env.AGUARA_WASM_EXEC)]],
            ['http://localhost/aguara.wasm', ['application/wasm', fs.readFileSync(process.env.AGUARA_WASM)]],
        ]);
        await page.route('**/*', route => {
            const asset = assets.get(route.request().url());
            if (asset) return route.fulfill({contentType: asset[0], body: asset[1]});
            requests.push(route.request().url());
            return route.abort();
        });
        await page.goto('http://localhost/');
        await page.waitForFunction(() => !document.getElementById('scan').disabled);
        const source = '# `<img src=x onerror=window.x=1>`\n\nwrite file overwrite modify file append to create file save to disk\n';
        const result = await page.evaluate(async content => JSON.parse(await aguaraScanContent(content, 'skill.md')), source);
        assert.ok(result.findings.some(f => f.rule_id === 'NLP_HEADING_MISMATCH'), JSON.stringify(result.findings.map(f => ({id: f.rule_id, name: f.rule_name}))));
        // The previous heading-to-name route was removed by the redaction fix.
        // Keep this integration control separate from hostile JSON renderer tests.
        assert.ok(result.findings.every(f => !f.rule_name.includes('<img')));
        await page.locator('#content').fill(source);
        await page.locator('#scan').click();
        await page.waitForFunction(() => document.querySelectorAll('.finding').length > 0);
        assert.equal(await page.locator('.finding').count(), result.findings.length);
        assert.equal(await page.locator('#results img, #results svg').count(), 0);
        assert.equal(await page.evaluate(() => window.x === 1), false);
        await page.locator('#content').fill('A short paragraph about ordinary documentation.');
        await page.locator('#scan').click();
        await page.waitForFunction(() => document.querySelector('.clean') !== null);
        assert.equal(await page.locator('.finding').count(), 0);
        await page.locator('[data-tab="rules"]').click();
        await page.locator('#rule-id').fill('PROMPT_INJECTION_001');
        await page.locator('#explain-btn').click();
        assert.equal(JSON.parse(await page.locator('#rule-detail').textContent()).id, 'PROMPT_INJECTION_001');
        assert.deepEqual(requests, []);
        assert.deepEqual(errors, []);
    } finally {
        await page.close();
    }
});
