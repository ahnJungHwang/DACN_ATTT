const fs=require('fs'),p=require('path'),crypto=require('crypto');
const rows=[];
function walk(dir,rel='') { for(const name of fs.readdirSync(dir).sort()) {
 const full=p.join(dir,name),key=rel?rel+'/'+name:name,s=fs.lstatSync(full);
 if(s.isSymbolicLink()) throw Error('Symlink requires manual backup review');
 if(s.isDirectory()) {rows.push({path:key,type:'directory',mode:s.mode&4095,uid:s.uid,gid:s.gid});walk(full,key);}
 else if(s.isFile()) rows.push({path:key,type:'file',size:s.size,mode:s.mode&4095,uid:s.uid,gid:s.gid,
 sha256:crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex')});
 else throw Error('Unsupported file type');
}}
walk('/source');process.stdout.write(JSON.stringify(rows));
