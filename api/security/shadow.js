const BLOCKED_SCHEMES = new Set(["file:","ftp:","gopher:","data:","javascript:","smb:"]);
const PRIVATE_HOSTS = new Set(["localhost","localhost.localdomain","broadcasthost"]);
function privateV4(h){const p=h.split(".").map(Number);if(p.length!==4||p.some(Number.isNaN))return false;const[a,b]=p;return a===10||a===127||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||(a===192&&b===168);}
function assess(raw){
 const u=new URL(raw), host=u.hostname.toLowerCase(), reasons=[]; let score=0;
 if(BLOCKED_SCHEMES.has(u.protocol)||!["http:","https:"].includes(u.protocol)) return {action:"BLOCK",score:100,reasons:["unsupported_scheme"]};
 if(PRIVATE_HOSTS.has(host)||privateV4(host)||host.endsWith(".local")||host.endsWith(".internal")){score+=100;reasons.push("private_or_local_destination");}
 if(!host.includes(".")){score+=25;reasons.push("non_fqdn_host");}
 const port=Number(u.port||(u.protocol==="https:"?443:80)); if([22,23,25,3389,5900].includes(port)){score+=30;reasons.push("sensitive_service_port");}
 const action=score>=100?"BLOCK":score>=70?"QUARANTINE":score>=40?"SHADOW":score>=20?"MONITOR":"ALLOW";
 return {action,score,reasons,host,port};
}
export default function handler(req,res){
 if(req.method!=="POST")return res.status(405).json({ok:false,error:"method_not_allowed"});
 try{const url=typeof req.body?.url==="string"?req.body.url:"";if(!url||url.length>2048)return res.status(400).json({ok:false,error:"invalid_url"});res.setHeader("Cache-Control","no-store");res.setHeader("X-Content-Type-Options","nosniff");return res.status(200).json({ok:true,...assess(url),enforcement:"control-plane-only"});}
 catch{return res.status(400).json({ok:false,error:"invalid_url"});}
}
