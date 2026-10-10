"use strict";
const el=id=>document.getElementById(id);
let cy;
async function api(path){
 const response=await fetch('/api/'+path,{headers:{'X-API-Key':el('key').value}});
 const data=await response.json(); if(!response.ok)throw new Error(data.detail||response.statusText);return data;
}
function inspect(data){el('details').textContent=JSON.stringify(data,null,2);}
function draw(data){
 const elements=data.nodes.map(n=>({data:{id:n.id,name:n.properties.name||n.id,label:n.label,evidence:n}}));
 data.edges.forEach((e,i)=>elements.push({data:{id:'edge-'+i,source:e.source,target:e.target,name:e.type,evidence:e,prediction:e.prediction},classes:e.prediction?'prediction':''}));
 if(cy)cy.destroy();
 cy=cytoscape({container:el('graph'),elements,layout:{name:'cose',animate:false},style:[
 {selector:'node',style:{'background-color':'#54d8b5','label':'data(name)','font-size':10,'color':'#d7e6f2','text-valign':'bottom','text-margin-y':7,'width':22,'height':22}},
 {selector:'edge',style:{'width':1.5,'line-color':'#375b73','target-arrow-color':'#375b73','target-arrow-shape':'triangle','curve-style':'bezier'}},
 {selector:'edge.prediction',style:{'line-style':'dashed','line-color':'#eab875'}},
 {selector:'node[label = "Vulnerability"]',style:{'background-color':'#eab875','shape':'diamond'}},
 {selector:':selected',style:{'border-width':3,'border-color':'#fff'}}]});
 cy.on('tap','node,edge',event=>inspect(event.target.data('evidence')));
 el('status').textContent=`${data.nodes.length} nodes · ${data.edges.length} edges${data.truncated?' · bounded view (truncated)':''}`;
}
async function run(fn){try{await fn();}catch(e){el('status').textContent=e.message;}}
el('load').onclick=()=>run(async()=>draw(await api('visualization?limit=200')));
el('quality').onclick=()=>run(async()=>inspect(await api('quality')));
el('search').onclick=()=>run(async()=>{
 const data=await api('search?q='+encodeURIComponent(el('query').value));el('results').replaceChildren();
 data.items.forEach(n=>{const button=document.createElement('button');button.textContent=n.label+' · '+(n.properties.name||n.id);button.onclick=()=>inspect(n);el('results').appendChild(button);});
});
