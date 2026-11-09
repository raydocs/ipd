import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

test('comparison requires explicit opt-in and renders untrusted values as text', async () => {
 const nodes=new Map();const urls=[];
 const get=id=>{if(!nodes.has(id))nodes.set(id,{value:'',checked:false,children:[],appendChild(child){this.children.push(child)},addEventListener(event,fn){this[event]=fn},set innerHTML(v){throw Error('unsafe HTML')}});return nodes.get(id)};
 vm.runInNewContext(readFileSync(new URL('./app.js',import.meta.url),'utf8'),{
  document:{getElementById:get,createElement:()=>({children:[],appendChild(child){this.children.push(child)},set innerHTML(v){throw Error('unsafe HTML')}})},window:{},fetch:async url=>{urls.push(url);return {ok:true,json:async()=>({data:{rows:[{fields:{country:'<img src=x onerror=alert(1)>'}}]},summary_md:'<script>untrusted</script>'})}}
 });
 const submit=()=>get('compare').submit({preventDefault(){}});
 submit();assert.equal(urls.length,0);
 get('ip').value='1.1.1.1';submit();assert.equal(urls.at(-1),'/v1/ip/1.1.1.1/compare?live=0');
 get('compare-live').checked=true;submit();assert.equal(urls.at(-1),'/v1/ip/1.1.1.1/compare?live=1');
 await new Promise(resolve=>setImmediate(resolve));
 assert.match(get('detail').textContent, /<img/);
 assert.match(get('comparison-rows').children.at(-1).children[2].textContent, /<img/);
 assert.equal(get('summary').textContent,'<script>untrusted</script>');
 get('q').submit({preventDefault(){}});assert.equal(urls.at(-1),'/v1/ip/1.1.1.1/risk?live=0');
});
