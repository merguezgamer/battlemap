const http   = require("http");
const fs     = require("fs");
const path   = require("path");
const { WebSocketServer } = require("ws");
const initSqlJs = require("sql.js");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const MIME = {
  ".html":"text/html",".js":"application/javascript",
  ".css":"text/css",".png":"image/png",".jpg":"image/jpeg",".svg":"image/svg+xml",
};

// ── DATABASE (sql.js — pur JS, zéro compilation) ──────────────────────────────
const DB_FILE = path.join(__dirname, "battlemap.db");
let db = null;
let dbReady = false;

function saveDb() {
  if (!db) return;
  try { fs.writeFileSync(DB_FILE, Buffer.from(db.export())); }
  catch(e) { console.warn("Erreur sauvegarde DB:", e.message); }
}
let _dbTimer=null;
function scheduleDbSave(){ clearTimeout(_dbTimer); _dbTimer=setTimeout(saveDb,2000); }

function dbRun(sql, p=[]){ if(db) { db.run(sql,p); scheduleDbSave(); } }
function dbGet(sql, p=[]){
  if(!db) return null;
  const s=db.prepare(sql); s.bind(p);
  const row=s.step()?s.getAsObject():null; s.free(); return row;
}
function dbAll(sql, p=[]){
  if(!db) return [];
  const s=db.prepare(sql); s.bind(p);
  const rows=[]; while(s.step())rows.push(s.getAsObject()); s.free(); return rows;
}

async function initDb(){
  try {
    const SQL = await initSqlJs();
    db = fs.existsSync(DB_FILE)
      ? new SQL.Database(fs.readFileSync(DB_FILE))
      : new SQL.Database();
    db.run(`
      CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL COLLATE NOCASE,
        password TEXT NOT NULL,
        created_at INTEGER DEFAULT(strftime('%s','now'))
      );
      CREATE TABLE IF NOT EXISTS sessions(
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at INTEGER DEFAULT(strftime('%s','now'))
      );
      CREATE TABLE IF NOT EXISTS campaigns(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        lobby_code TEXT UNIQUE NOT NULL,
        state TEXT NOT NULL DEFAULT '{}',
        updated_at INTEGER DEFAULT(strftime('%s','now'))
      );
    `);
    saveDb();
    dbReady = true;
    console.log(fs.existsSync(DB_FILE) ? "💾  DB chargée" : "💾  Nouvelle DB créée");
  } catch (err) {
    console.error("Impossible d'initialiser la DB:", err);
  }
}

function genToken(){ return crypto.randomBytes(32).toString("hex"); }
function genCode() { return Math.random().toString(36).substring(2,8).toUpperCase(); }

// ── AUTH HELPERS ──────────────────────────────────────────────────────────────
function getToken(req){ const a=req.headers["authorization"]||""; return a.startsWith("Bearer ")?a.slice(7):null; }
function getSession(req){
  const token=getToken(req); if(!token)return null;
  return dbGet("SELECT s.*,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?",[token]);
}

// ── LOBBY STATE ───────────────────────────────────────────────────────────────
const lobbies={};

function newLobbyState(hostId,hostName){
  return{hostId,hostName,imageUrl:"",tokens:{},drawings:{},obstacles:{},initiatives:{},playerNames:{[hostId]:hostName}};
}

function loadLobby(code){
  if(lobbies[code])return;
  const row=dbGet("SELECT * FROM campaigns WHERE lobby_code=?",[code]);
  if(row)lobbies[code]={...JSON.parse(row.state),players:{}};
}

function saveLobby(code){
  if(!lobbies[code])return;
  const l=lobbies[code];
  const state=JSON.stringify({hostId:l.hostId,imageUrl:l.imageUrl,tokens:l.tokens,drawings:l.drawings,obstacles:l.obstacles,initiatives:l.initiatives,playerNames:l.playerNames});
  dbRun("UPDATE campaigns SET state=?,updated_at=strftime('%s','now') WHERE lobby_code=?",[state,code]);
}
let _saveTimers={};
function scheduleSave(code){ clearTimeout(_saveTimers[code]); _saveTimers[code]=setTimeout(()=>saveLobby(code),2000); }

function publicState(code){
  const l=lobbies[code];
  return{hostId:l.hostId,imageUrl:l.imageUrl,tokens:l.tokens,drawings:l.drawings,obstacles:l.obstacles,initiatives:l.initiatives,playerIds:Object.keys(l.players),playerNames:l.playerNames};
}
function broadcast(code,msg,excludeId=null){
  const l=lobbies[code]; if(!l)return;
  const payload=JSON.stringify(msg);
  for(const[id,ws]of Object.entries(l.players))
    if(id!==excludeId&&ws&&ws.readyState===1)ws.send(payload);
}
function broadcastAll(code,msg){broadcast(code,msg,null);}

// ── HTTP ──────────────────────────────────────────────────────────────────────
function readBody(req){ return new Promise(res=>{let d="";req.on("data",c=>d+=c);req.on("end",()=>res(d));}); }
function json(res,status,obj){res.writeHead(status,{"Content-Type":"application/json"});res.end(JSON.stringify(obj));}

const httpServer = http.createServer(async(req,res)=>{
  // Sécurité anti-crash si la DB n'est pas encore chargée
  if (!dbReady) {
    return json(res, 503, { error: "Serveur en cours de démarrage, réessaye." });
  }

  const url=new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const body=await readBody(req);

  if(req.method==="POST"&&url.pathname==="/api/register"){
    const{username,password}=JSON.parse(body||"{}");
    if(!username||!password||username.length<3||password.length<6)
      return json(res,400,{error:"Pseudo (3+) et mot de passe (6+) requis."});
    if(dbGet("SELECT id FROM users WHERE username=?",[username]))
      return json(res,409,{error:"Pseudo déjà pris."});
    const hash=bcrypt.hashSync(password,10);
    dbRun("INSERT INTO users(username,password)VALUES(?,?)",[username,hash]);
    const user=dbGet("SELECT * FROM users WHERE username=?",[username]);
    const token=genToken();
    dbRun("INSERT INTO sessions(token,user_id)VALUES(?,?)",[token,user.id]);
    return json(res,200,{token,username:user.username,userId:user.id});
  }

  if(req.method==="POST"&&url.pathname==="/api/login"){
    const{username,password}=JSON.parse(body||"{}");
    const user=dbGet("SELECT * FROM users WHERE username=?",[username]);
    if(!user||!bcrypt.compareSync(password,user.password))
      return json(res,401,{error:"Identifiants incorrects."});
    const token=genToken();
    dbRun("INSERT INTO sessions(token,user_id)VALUES(?,?)",[token,user.id]);
    return json(res,200,{token,username:user.username,userId:user.id});
  }

  if(req.method==="POST"&&url.pathname==="/api/logout"){
    const token=getToken(req); if(token)dbRun("DELETE FROM sessions WHERE token=?",[token]);
    return json(res,200,{ok:true});
  }

  if(req.method==="GET"&&url.pathname==="/api/me"){
    const s=getSession(req); if(!s)return json(res,401,{error:"Non connecté."});
    return json(res,200,{username:s.username,userId:s.user_id});
  }

  if(req.method==="GET"&&url.pathname==="/api/campaigns"){
    const s=getSession(req); if(!s)return json(res,401,{error:"Non connecté."});
    return json(res,200,dbAll("SELECT id,name,lobby_code,updated_at FROM campaigns WHERE user_id=? ORDER BY updated_at DESC",[s.user_id]));
  }

  if(req.method==="POST"&&url.pathname==="/api/campaigns"){
    const s=getSession(req); if(!s)return json(res,401,{error:"Non connecté."});
    const{name}=JSON.parse(body||"{}"); if(!name)return json(res,400,{error:"Nom requis."});
    let code; do{code=genCode();}while(dbGet("SELECT id FROM campaigns WHERE lobby_code=?",[code]));
    dbRun("INSERT INTO campaigns(user_id,name,lobby_code,state)VALUES(?,?,?,?)",[s.user_id,name,code,JSON.stringify(newLobbyState("mj_"+s.user_id,s.username))]);
    const camp=dbGet("SELECT id FROM campaigns WHERE lobby_code=?",[code]);
    return json(res,200,{id:camp.id,name,lobby_code:code});
  }

  if(req.method==="DELETE"&&url.pathname.startsWith("/api/campaigns/")){
    const s=getSession(req); if(!s)return json(res,401,{error:"Non connecté."});
    const id=parseInt(url.pathname.split("/").pop());
    dbRun("DELETE FROM campaigns WHERE id=? AND user_id=?",[id,s.user_id]);
    return json(res,200,{ok:true});
  }

  if(req.method==="PATCH"&&url.pathname.startsWith("/api/campaigns/")){
    const s=getSession(req); if(!s)return json(res,401,{error:"Non connecté."});
    const id=parseInt(url.pathname.split("/").pop());
    const{name}=JSON.parse(body||"{}");
    if(name)dbRun("UPDATE campaigns SET name=? WHERE id=? AND user_id=?",[name,id,s.user_id]);
    return json(res,200,{ok:true});
  }

  // Static files handler
  const filePath=path.join(__dirname,url.pathname==="/"?"index.html":url.pathname);
  fs.readFile(filePath,(err,data)=>{
    if(err){res.writeHead(404);return res.end("Not found");}
    res.writeHead(200,{"Content-Type":MIME[path.extname(filePath)]||"text/plain"});
    res.end(data);
  });
});

// ── WEBSOCKET ─────────────────────────────────────────────────────────────────
const wss=new WebSocketServer({server:httpServer});
wss.on("connection",ws=>{
  let currentLobby=null,currentId=null;

  ws.on("message",raw=>{
    let msg; try{msg=JSON.parse(raw);}catch{return;}
    const lobby=lobbies[currentLobby];

    switch(msg.type){
      case"JOIN_LOBBY":{
        const code=msg.code?.toUpperCase();
        loadLobby(code);
        if(!lobbies[code]){ws.send(JSON.stringify({type:"ERROR",message:"Lobby introuvable."}));return;}
        const userId=msg.userId||genCode();
        currentId=userId;currentLobby=code;
        lobbies[code].players[userId]=ws;
        lobbies[code].playerNames[userId]=msg.name||"Joueur";
        ws.send(JSON.stringify({type:"LOBBY_JOINED",code,userId,state:publicState(code)}));
        broadcastAll(code,{type:"PLAYER_UPDATE",playerIds:Object.keys(lobbies[code].players),playerNames:lobbies[code].playerNames});
        scheduleSave(code);break;
      }

      case"JOIN_CAMPAIGN":{
        const{token,lobbyCode:code}=msg;
        const session=dbGet("SELECT s.*,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?",[token]);
        if(!session){ws.send(JSON.stringify({type:"ERROR",message:"Session expirée."}));return;}
        const camp=dbGet("SELECT * FROM campaigns WHERE lobby_code=?",[code]);
        if(!camp||String(camp.user_id)!==String(session.user_id)){ws.send(JSON.stringify({type:"ERROR",message:"Campagne introuvable."}));return;}
        loadLobby(code);
        const userId="mj_"+session.user_id;
        currentId=userId;currentLobby=code;
        lobbies[code].players[userId]=ws;
        lobbies[code].playerNames[userId]=session.username;
        lobbies[code].hostId=userId;
        ws.send(JSON.stringify({type:"LOBBY_JOINED",code,userId,isMJ:true,state:publicState(code)}));
        broadcastAll(code,{type:"PLAYER_UPDATE",playerIds:Object.keys(lobbies[code].players),playerNames:lobbies[code].playerNames});
        break;
      }

      case"SET_TOKEN":{
        if(!lobby)return;
        const{tokenId,x,y,color,label,notes,hp,maxHp,size,sizeN,conditions}=msg;
        const ex=lobby.tokens[tokenId];
        if(ex&&ex.userId!==currentId&&lobby.hostId!==currentId)return;
        lobby.tokens[tokenId]={tokenId,x,y,color,label,
          notes:notes??ex?.notes??"",hp:hp??ex?.hp??null,maxHp:maxHp??ex?.maxHp??null,
          size:size??ex?.size??"Medium",sizeN:sizeN??ex?.sizeN??1,
          conditions:conditions??ex?.conditions??[],
          userId:ex?ex.userId:currentId,ranges:ex?.ranges??[]};
        broadcastAll(currentLobby,{type:"SET_TOKEN",token:lobby.tokens[tokenId]});
        scheduleSave(currentLobby);break;
      }

      case"DELETE_TOKEN":{
        if(!lobby)return;
        const ex=lobby.tokens[msg.tokenId];
        if(!ex||(ex.userId!==currentId&&lobby.hostId!==currentId))return;
        delete lobby.tokens[msg.tokenId];
        lobby.initiatives=Object.fromEntries(Object.entries(lobby.initiatives||{}).filter(([k])=>k!==msg.tokenId));
        broadcastAll(currentLobby,{type:"DELETE_TOKEN",tokenId:msg.tokenId});
        scheduleSave(currentLobby);break;
      }

      case"SET_RANGES":{
        if(!lobby)return;
        const tok=lobby.tokens[msg.tokenId];
        if(!tok||(tok.userId!==currentId&&lobby.hostId!==currentId))return;
        tok.ranges=msg.ranges;
        broadcastAll(currentLobby,{type:"SET_RANGES",tokenId:msg.tokenId,ranges:msg.ranges});
        scheduleSave(currentLobby);break;
      }

      case"SET_DRAWING":{
        if(!lobby)return;
        const{drawId,drawType,points,color,width}=msg;
        lobby.drawings[drawId]={drawId,drawType,points,color,width,userId:currentId};
        broadcastAll(currentLobby,{type:"SET_DRAWING",drawing:lobby.drawings[drawId]});
        scheduleSave(currentLobby);break;
      }
      case"DELETE_DRAWING":{
        if(!lobby)return;
        const ex=lobby.drawings[msg.drawId];
        if(!ex||(ex.userId!==currentId&&lobby.hostId!==currentId))return;
        delete lobby.drawings[msg.drawId];
        broadcastAll(currentLobby,{type:"DELETE_DRAWING",drawId:msg.drawId});
        scheduleSave(currentLobby);break;
      }
      case"CLEAR_DRAWINGS":{
        if(!lobby||lobby.hostId!==currentId)return;
        lobby.drawings={};broadcastAll(currentLobby,{type:"CLEAR_DRAWINGS"});scheduleSave(currentLobby);break;
      }

      case"SET_OBSTACLE":{
        if(!lobby||lobby.hostId!==currentId)return;
        const{obsId,obsType,x,y,rotation,scale:sc}=msg;
        lobby.obstacles[obsId]={obsId,obsType,x,y,rotation:rotation||0,scale:sc||1};
        broadcastAll(currentLobby,{type:"SET_OBSTACLE",obstacle:lobby.obstacles[obsId]});
        scheduleSave(currentLobby);break;
      }
      case"DELETE_OBSTACLE":{
        if(!lobby||lobby.hostId!==currentId)return;
        delete lobby.obstacles[msg.obsId];
        broadcastAll(currentLobby,{type:"DELETE_OBSTACLE",obsId:msg.obsId});
        scheduleSave(currentLobby);break;
      }
      case"CLEAR_OBSTACLES":{
        if(!lobby||lobby.hostId!==currentId)return;
        lobby.obstacles={};broadcastAll(currentLobby,{type:"CLEAR_OBSTACLES"});scheduleSave(currentLobby);break;
      }

      case"SET_INITIATIVES":{
        if(!lobby||lobby.hostId!==currentId)return;
        lobby.initiatives=msg.initiatives;
        broadcastAll(currentLobby,{type:"SET_INITIATIVES",initiatives:msg.initiatives});
        scheduleSave(currentLobby);break;
      }

      case"PING":
        if(!lobby)return;
        broadcastAll(currentLobby,{type:"PING",x:msg.x,y:msg.y,color:msg.color});break;

      case"DICE_ROLL":
        if(!lobby)return;
        broadcastAll(currentLobby,{type:"DICE_ROLL",userId:currentId,
          name:lobby.playerNames[currentId],dice:msg.dice,result:msg.result,rolls:msg.rolls});break;

      case"SET_IMAGE":
        if(!lobby||lobby.hostId!==currentId)return;
        lobby.imageUrl=msg.imageUrl;
        broadcastAll(currentLobby,{type:"SET_IMAGE",imageUrl:msg.imageUrl});
        scheduleSave(currentLobby);break;

      case"CLEAR_ALL":
        if(!lobby||lobby.hostId!==currentId)return;
        lobby.tokens={};lobby.drawings={};lobby.obstacles={};lobby.initiatives={};
        broadcastAll(currentLobby,{type:"CLEAR_ALL"});scheduleSave(currentLobby);break;
    }
  });

  ws.on("close",()=>{
    if(!currentLobby||!lobbies[currentLobby])return;
    const l=lobbies[currentLobby];
    delete l.players[currentId];delete l.playerNames[currentId];
    const remaining=Object.keys(l.players);
    if(l.hostId===currentId&&remaining.length>0){
      l.hostId=remaining[0];
      broadcastAll(currentLobby,{type:"HOST_CHANGED",newHostId:l.hostId});
    }
    broadcastAll(currentLobby,{type:"PLAYER_UPDATE",playerIds:remaining,playerNames:l.playerNames});
    saveLobby(currentLobby);
  });
});

// ── START ─────────────────────────────────────────────────────────────────────
const PORT=process.env.PORT||3000;

initDb().then(()=>{
  // On ne lance l'écoute du port que si on n'est pas dans l'environnement de build Vercel
  if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
    httpServer.listen(PORT,()=>{
      console.log(`\n⚔  Battlemap  →  http://localhost:${PORT}`);
      console.log(`🗄  Base       →  battlemap.db\n`);
    });
  }
});

// Indispensable pour que Vercel trouve le point d'entrée de l'application
module.exports = httpServer;