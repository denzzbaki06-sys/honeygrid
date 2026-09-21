const { test } = require('node:test');
const assert = require('node:assert/strict');
const { appendEvent } = require('../../main/resources/static/event-view.js');
function fixture() {
  const container = { children: [], appendChild(row) { this.children.push(row); row.remove = () => this.children.splice(this.children.indexOf(row), 1); }, get firstElementChild() { return this.children[0]; } };
  const document = { createElement() { return { set innerHTML(value) { throw Error('Unsafe HTML sink used'); } }; } };
  return { document, container };
}
test('hostile payload and IP are rendered as text', () => {
  const { document, container } = fixture();
  const payload = '<img src=x onerror=alert(1)>';
  const row = appendEvent(document, container, { ipAddress: '<svg onload=alert(2)>', payload, port: 8082 });
  assert.ok(row.textContent.includes(payload));
  assert.ok(row.textContent.includes('<svg onload=alert(2)>'));
});
test('stream DOM remains bounded and never claims OS blocking', () => {
  const { document, container } = fixture();
  for (let i=0;i<350;i++) appendEvent(document,container,{payload:String(i),thresholdExceeded:true});
  assert.equal(container.children.length,300);
  assert.ok(container.children.at(-1).textContent.includes('NOT BLOCKED'));
});
