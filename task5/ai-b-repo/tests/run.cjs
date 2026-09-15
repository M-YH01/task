const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const spec = JSON.parse(fs.readFileSync(path.join(__dirname, 'cases.json'), 'utf8'));
const start = source.indexOf('  function restoreFromProject(proj)');
const end = source.indexOf('  $("importJsonInput").addEventListener', start);
assert(start >= 0 && end > start, '복원 함수 구간을 찾을 수 없습니다. 검사 의미를 보존하며 어댑터를 점검하세요.');
const restore = source.slice(start, end);
const layerStart = source.indexOf('  function newLayer(overrides)');
const layerEnd = source.indexOf('  function addLayer(', layerStart);
function harness() {
  const errors = [], successes = [], images = [];
  let uid = 0;
  const ctx = {state:{aspectId:'16:9', layers:[{id:'old', text:'기존 작업'}],activeLayerId:'old',image:{name:'old image'}},
    ASPECTS:[{id:'1:1'},{id:'4:5'},{id:'16:9'}], uid:()=>`test-${++uid}`,
    showError:msg=>errors.push(msg), showOk:msg=>successes.push(msg), clearError:()=>{},
    buildAspectRow:()=>{}, setupCanvasSize:()=>{}, renderLayerChips:()=>{}, syncControlsFromActive:()=>{}, render:()=>{},
    imgInfo:{textContent:'기존 이미지'}, Image:class {constructor(){images.push(this);}}};
  vm.createContext(ctx);
  vm.runInContext(source.slice(layerStart, layerEnd) + restore, ctx);
  return {ctx, errors, successes, images};
}
const results = spec.cases.map(c => {
  const h = harness();
  const before = JSON.stringify(h.ctx.state);
  let input = structuredClone(spec.valid);
  if ('root' in c) input = c.root;
  if (c.patch) Object.assign(input, c.patch);
  if (c.layerPatch) Object.assign(input.layers[0], c.layerPatch);
  if (c.mode === 'imageLoad') input.image = spec.png;
  try {
    h.ctx.restoreFromProject(input);
    if (c.mode === 'imageError') {
      assert.equal(h.images.length, 1, '디코더 1회');
      h.images[0].onerror();
    }
    if (c.mode === 'reject' || c.mode === 'imageError') {
      assert.equal(JSON.stringify(h.ctx.state), before, '거부/실패 시 기존 상태 보존');
      assert(h.errors.length > 0, '오류 표시');
      assert.equal(h.successes.length, 0, '성공 표시 없음');
      if (c.noImageRequest) assert.equal(h.images.length, 0, '외부 이미지 요청 없음');
    } else {
      if (c.mode === 'imageLoad') {
        assert.equal(JSON.stringify(h.ctx.state), before, '이미지 로딩 중 기존 상태 보존');
        assert.equal(h.successes.length, 0, '로드 전 성공 표시 없음');
        assert.equal(h.images.length, 1);
        h.images[0].onload();
        assert.equal(h.ctx.state.image.img, h.images[0]);
      } else assert.equal(h.ctx.state.image, null);
      assert.equal(h.ctx.state.aspectId, '4:5');
      assert.equal(h.ctx.state.layers[0].text, '안녕하세요');
      assert.equal(h.ctx.state.activeLayerId, h.ctx.state.layers[0].id);
      assert.equal(h.successes.length, 1);
      assert.equal(h.errors.length, 0);
    }
    return {id:c.id, name:c.name, pass:true};
  } catch (err) {return {id:c.id, name:c.name, pass:false, error:err.message};}
});
const output = {recordedAt:new Date().toISOString(), sourceSha256:crypto.createHash('sha256').update(source).digest('hex'),
  passed:results.filter(r=>r.pass).length, total:results.length, results};
console.log(JSON.stringify(output, null, 2));
if (process.argv[2]) fs.writeFileSync(path.resolve(process.argv[2]), JSON.stringify(output, null, 2)+'\n');
process.exitCode = output.passed === output.total ? 0 : 1;
