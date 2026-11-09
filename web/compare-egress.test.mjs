import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

test('comparison target must not replace local WebRTC egress',async()=>{
 const nodes=new Map();let captured;
 const get=id=>{if(!nodes.has(id))nodes.set(id,{value:'',checked:false,children:[],appendChild(c){this.children.push(c)},addEventListener(ev,fn){this[ev]=fn},set innerHTML(_){throw Error('unsafe HTML')}});return nodes.get(id)};
 class PC {
  createDataChannel(){} close(){}
  createOffer(){return Promise.resolve({})}
  setLocalDescription(){queueMicrotask(()=>this.onicecandidate({candidate:null}));return Promise.resolve()}
 }
 vm.runInNewContext(readFileSync(new URL('./app.js',import.meta.url),'utf8'),{
  document:{getElementById:get,createElement:()=>({children:[],appendChild(c){this.children.push(c)}})},
  window:{RTCPeerConnection:PC,ipdJudge:{judgeLeak(egress){captured=[...egress];return {leak:false,candidate_count:0}}}},
  RTCPeerConnection:PC,setTimeout,clearTimeout,
  fetch:async url=>({ok:true,json:async()=>url==='/v1/me'?{data:{ipv4:'1.1.1.1'}}:{data:{ip:'8.8.8.8',rows:[]}}})
 });
 const flush=()=>new Promise(resolve=>setImmediate(resolve));
 get('q').submit({preventDefault(){}});await flush();
 get('ip').value='8.8.8.8';get('compare').submit({preventDefault(){}});await flush();
 get('webrtc').click();await flush();
 assert.deepEqual(captured,['1.1.1.1'],'third-party lookup target overwrote caller egress');
});
