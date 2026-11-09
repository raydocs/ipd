import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('./report.js',import.meta.url),'utf8');
function helpers(){const root={};vm.runInNewContext(source,root);return root.ipdReport;}
test('unknown facts and zero/invalid/unattributed locations stay unknown',()=>{
 const h=helpers();
 for(const geo of [{lat:0,lon:0,sources:[{}]},{lat:null,lon:null,sources:[{}]},{lat:'12',lon:3,sources:[{}]},{lat:91,lon:0,sources:[{}]},{lat:1,lon:181,sources:[{}]},{lat:1,lon:2,sources:[]}]){
  const m=h.model({data:{geo}});assert.equal(m.point,null);assert.equal(m.verdict,'unknown');assert.ok(m.facts.every(f=>f.value==='unknown'));
 }
 const m=h.model({verdict:'ok',data:{geo:{lat:0,lon:1,sources:[{id:'synthetic'}]}}});assert.equal(m.point.y,130);assert.ok(m.point.x>300);
});
test('share SVG only contains controlled summary, never raw report data',()=>{
 const h=helpers();
 const svg=h.shareSVG({verdict:'"><script>SECRET_TOKEN</script>',summary_md:'SECRET_TOKEN',sources:[{raw:{key:'SECRET_TOKEN'}}],data:{ip:'203.0.113.29',geo:{lat:30,lon:60,city:'SECRET_TOKEN',sources:[{}]},error:'SECRET_TOKEN',purity:{score:100},rows:[{fields:{password:'SECRET_TOKEN'}}]}});
 assert.match(svg,/IP HIDDEN/);assert.match(svg,/未知/);assert.match(svg,/Sources: 1/);
 for(const text of ['SECRET_TOKEN','203.0.113.29','<script','href=','onload=','foreignObject','30,60'])assert.ok(!svg.includes(text),text);
});
test('UI integrates report asset, accessible query and default-disabled local sharing',()=>{
 const html=readFileSync(new URL('./index.html',import.meta.url),'utf8');
 assert.match(html,/id="share-opt-in"/);assert.doesNotMatch(html,/id="share-opt-in"[^>]*checked/);
 assert.match(html,/id="share-download" disabled/);assert.match(html,/for="ip"/);assert.ok(html.includes("/static/report.js"));
 const css=readFileSync(new URL('./style.css',import.meta.url),'utf8');assert.match(css,/prefers-reduced-motion/);assert.match(css,/focus-visible/);
});
test('report requests discard stale results and reset opt-in on refresh/failure',async()=>{
 const nodes=new Map(), pending=[],downloads=[];
 const get=id=>{if(!nodes.has(id))nodes.set(id,{value:'',checked:false,children:[],appendChild(n){this.children.push(n)},setAttribute(k,v){this[k]=v},addEventListener(k,fn){this[k]=fn},set textContent(v){this.text=v;this.children=[]},get textContent(){return this.text}});return nodes.get(id)};
 const context={document:{getElementById:get,createElement:()=>({children:[],appendChild(c){this.children.push(c)}})},window:{ipdReport:helpers()},fetch:url=>new Promise(resolve=>pending.push({url,resolve})),Blob,URL:{createObjectURL(){downloads.push(1);return 'blob:local'}},setTimeout};
 vm.runInNewContext(readFileSync(new URL('./app.js',import.meta.url),'utf8'),context);
 const submit=()=>get('q').submit({preventDefault(){}});
 get('ip').value='203.0.113.29';submit();get('ip').value='203.0.113.30';submit();
 pending[1].resolve({ok:true,json:async()=>({verdict:'caveat',summary_md:'LATEST',data:{}})});
 const flush=()=>new Promise(resolve=>setImmediate(resolve));await flush();
 get('share-opt-in').checked=true;get('share-opt-in').change();assert.equal(get('share-download').disabled,false);
 pending[0].resolve({ok:true,json:async()=>({verdict:'ok',summary_md:'STALE',data:{}})});await flush();assert.equal(get('summary').textContent,'LATEST');
 submit();assert.equal(get('share-download').disabled,true);assert.equal(get('share-opt-in').checked,false);
 pending[2].resolve({ok:false});await flush();get('share-opt-in').checked=true;get('share-download').click();assert.equal(downloads.length,0);assert.equal(get('detail').textContent,'');
});

test('older request cannot overwrite the latest report',async()=>{
 const nodes=new Map(),pending=[];
 const get=id=>{if(!nodes.has(id))nodes.set(id,{value:'',checked:false,children:[],appendChild(n){this.children.push(n)},addEventListener(k,fn){this[k]=fn}});return nodes.get(id)};
 const context={document:{getElementById:get,createElement:()=>({appendChild(){}})},window:{},fetch:()=>new Promise(resolve=>pending.push(resolve))};
 const code=readFileSync(process.env.IPD_TEST_APP_SOURCE || new URL('./app.js',import.meta.url),'utf8');
 vm.runInNewContext(code,context);
 get('ip').value='203.0.113.29';get('q').submit({preventDefault(){}});
 get('ip').value='203.0.113.30';get('q').submit({preventDefault(){}});
 const flush=()=>new Promise(resolve=>setImmediate(resolve));
 pending[1]({ok:true,json:async()=>({summary_md:'LATEST',data:{}})});await flush();
 pending[0]({ok:true,json:async()=>({summary_md:'STALE',data:{}})});await flush();
 assert.equal(get('summary').textContent,'LATEST');
});

test('me, lookup, risk and compare preserve known facts without extra requests',()=>{
 const h=helpers();
 for(const [rep,want] of [
  [{data:{ipv4:'203.0.113.29',type:'residential_fixed',cc:'ZZ',asn:64512}},['residential_fixed','unknown','ZZ','64512']],
  [{data:{residential:{class:'hosting'},native:{verdict:'abstain'}}},['hosting','abstain','unknown','unknown']],
  [{data:{geo:{cc:'ZZ'},asn:{asn:64512}}},['unknown','unknown','ZZ','64512']],
  [{data:{rows:[]}},['unknown','unknown','unknown','unknown']]
 ])assert.deepEqual(Array.from(h.model(rep).facts,f=>f.value),want);
});

test('empty lookup and compare completely reset the prior report',async()=>{
 const nodes=new Map(),requests=[];
 const get=id=>{if(!nodes.has(id))nodes.set(id,{value:'',checked:false,children:[],appendChild(n){this.children.push(n)},addEventListener(k,fn){this[k]=fn},set textContent(v){this.text=v;this.children=[]},get textContent(){return this.text}});return nodes.get(id)};
 vm.runInNewContext(readFileSync(new URL('./app.js',import.meta.url),'utf8'),{document:{getElementById:get,createElement:()=>({appendChild(){}})},window:{ipdReport:helpers()},fetch:async url=>{requests.push(url);return {ok:true,json:async()=>({verdict:'safe',summary_md:'OLD_REPORT',data:{ip:'203.0.113.29',rows:[{id:'synthetic',fields:{country:'ZZ'}}]}})}}});
 for(const action of ['lookup','compare']){
  get('ip').value='203.0.113.29';get('compare').submit({preventDefault(){}});await new Promise(r=>setImmediate(r));
  assert.equal(get('comparison-wrap').hidden,false);
  get('ip').value='';
  if(action==='lookup')get('lookup').click();else get('compare').submit({preventDefault(){}});
  assert.equal(get('detail').textContent,'');assert.equal(get('verdict').textContent,'');
  assert.equal(get('comparison-wrap').hidden,true);assert.equal(get('comparison-results').hidden,true);assert.equal(get('comparison-rows').children.length,0);
  assert.equal(get('share-controls').hidden,true);assert.equal(get('location-panel').hidden,true);
 }
 assert.equal(requests.length,2);
});
