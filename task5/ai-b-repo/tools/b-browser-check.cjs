const {chromium} = require(require('child_process').execSync('npm root -g').toString().trim()+'/playwright');
const path=require('path'); const fs=require('fs');
const spec=JSON.parse(fs.readFileSync('ai-b-work/tests/cases.json','utf8'));
const buf=o=>({name:'p.json',mimeType:'application/json',buffer:Buffer.from(typeof o==='string'?o:JSON.stringify(o))});
const valid=spec.valid, withImg={...valid,image:spec.png}, badImg={...valid,image:'data:image/png;base64,AAAA'};
(async()=>{
  const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium'}).catch(()=>chromium.launch());
  const out=[];
  async function run(name, files){
    const p=await b.newPage(); const errs=[]; p.on('pageerror',e=>errs.push(e.message));
    await p.goto('file://'+path.resolve('ai-b-work/index.html'));
    const snap=()=>p.evaluate(()=>({aspect:[...document.querySelectorAll('#aspectRow [aria-pressed="true"], #aspectRow .active, #aspectRow .on')].map(e=>e.textContent.trim()).join('|'),
      chips:document.querySelector('#layerChips').textContent.trim().slice(0,60), img:document.querySelector('#imgInfo').textContent,
      err:document.querySelector('.show') && [...document.querySelectorAll('.show')].map(e=>e.textContent.trim()).join(' / ')}));
    const before=await snap();
    for(const f of files){ await p.setInputFiles('#importJsonInput', buf(f)); }
    await p.waitForTimeout(800);
    out.push({name, before, after:await snap(), pageErrors:errs}); await p.close();
  }
  await run('정상 JSON(이미지 없음)',[valid]);
  await run('정상 JSON(PNG 포함)',[withImg]);
  await run('손상 JSON 텍스트',['{"version":1,']);
  await run('디코딩 실패 PNG',[badImg]);
  await run('연속 복원: PNG 후 손상PNG',[withImg,badImg]);
  await run('연속 복원: 손상PNG 후 정상',[badImg,valid]);
  console.log(JSON.stringify(out,null,1)); fs.writeFileSync('ai-b-work/evidence/b-browser-check.json',JSON.stringify({recordedAt:new Date().toISOString(),browser:b.version(),results:out},null,2)+'\n');
  await b.close();
})();
