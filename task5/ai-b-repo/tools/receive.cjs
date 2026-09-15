// Dependency-free, model-neutral handoff receiver. Does not contact any LLM.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const destination = process.argv[2] && path.resolve(process.argv[2]);
if (!destination || fs.existsSync(destination)) throw new Error('새 폴더 경로를 지정하세요. 기존 폴더는 덮어쓰지 않습니다.');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'handoff-manifest.json'), 'utf8'));
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const checked = [];
for (const [file, expected] of Object.entries(manifest.files)) {
  if (path.isAbsolute(file) || file.split(/[\\/]/).includes('..')) throw new Error('잘못된 manifest 경로');
  const bytes = fs.readFileSync(path.join(root, file));
  if (sha(bytes) !== expected) throw new Error(`인수인계 파일 불일치: ${file}`);
  checked.push([file, bytes]);
}
fs.mkdirSync(destination, {recursive:true});
for (const [file, bytes] of checked) {
  const target = path.join(destination, file);
  fs.mkdirSync(path.dirname(target), {recursive:true});
  fs.writeFileSync(target, bytes);
}
fs.copyFileSync(path.join(root, 'handoff-manifest.json'), path.join(destination, 'handoff-manifest.json'));
const receipt = {receivedAt:new Date().toISOString(),
  role:process.argv.includes('--rehearsal-a')?'A reproduction only':'B receiver (session identity must be confirmed by B)',
  codeCommit:manifest.codeCommit, expectedHandoffSha256:manifest.files['HANDOFF.md'],
  receivedHandoffSha256:sha(fs.readFileSync(path.join(destination, 'HANDOFF.md'))),
  allFilesMatch:true, checkedFiles:checked.length,
  transcriptProvided:'Not determined by this script; B must attest separately'};
fs.mkdirSync(path.join(destination, 'evidence'), {recursive:true});
fs.writeFileSync(path.join(destination, 'evidence', 'receipt.json'), JSON.stringify(receipt,null,2)+'\n');
console.log(JSON.stringify(receipt,null,2));
