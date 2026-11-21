const crypto=require('crypto');
const {Pool}=require('pg');
let pool;
const id=()=>crypto.randomBytes(18).toString('hex');
const hash=(pass,salt)=>crypto.scryptSync(pass,salt,64).toString('hex');
const sections=['Новости проекта','Общение','Государственные организации','Автомобили и транспорт','Жалобы и предложения'];
function pub(u){return {id:u.id,nick:u.nick,joined:u.joined,bio:u.bio||'',avatar:u.avatar||'',role:u.role==='admin'?'admin':'player',banned:!!u.banned,online:!u.banned&&!!u.lastSeen&&Date.now()-u.lastSeen<45000}}
const fail=(status,message)=>{let e=new Error(message);e.status=status;throw e};
module.exports=async function handler(req,res){
 res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
 const send=(code,obj)=>res.status(code).json(obj);
 if(!process.env.DATABASE_URL)return send(503,{error:'Не подключена база данных. Добавьте DATABASE_URL в настройках Vercel → Environment Variables.'});
 if(!pool)pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false},max:3,connectionTimeoutMillis:8000});
 const client=await pool.connect().catch(()=>null);
 if(!client)return send(503,{error:'Нет соединения с базой данных. Проверьте DATABASE_URL.'});
 try{
  await client.query('CREATE TABLE IF NOT EXISTS rp196_store (id integer PRIMARY KEY, state jsonb NOT NULL)');
  await client.query('INSERT INTO rp196_store(id,state) VALUES(1,$1::jsonb) ON CONFLICT (id) DO NOTHING',[JSON.stringify({users:[],sessions:{},topics:[],apps:[]})]);
  await client.query('BEGIN');
  const row=await client.query('SELECT state FROM rp196_store WHERE id=1 FOR UPDATE');
  const db=row.rows[0].state; db.users||=[];db.sessions||={};db.topics||=[];db.apps||=[];
  const path=(Array.isArray(req.query.path)?req.query.path.join('/'):req.query.path||'').replace(/^\/+|\/+$/g,'');
  const d=req.body&&typeof req.body==='object'?req.body:{};
  const token=(req.headers.authorization||'').match(/^Bearer ([a-f0-9]{64})$/)?.[1];
  const session=token&&db.sessions[token];
  const user=session&&session.expires>Date.now()?db.users.find(u=>u.id===session.uid&&!u.banned):null;
  const auth=()=>{if(!user)fail(401,'Сначала войди в аккаунт');return user};
  const isAdmin=()=>user?.role==='admin';
  const admin=()=>{auth();if(!isAdmin())fail(403,'Недостаточно прав');let k=req.headers['x-admin-access'];if(!k||!session.adminGrant||k!==session.adminGrant||session.adminUntil<Date.now())fail(403,'Введите код администратора заново');};
  let code=200,out={ok:true};
  if(path==='state'&&req.method==='GET'){
   if(user){user.lastSeen=Date.now();session.expires=Date.now()+30*86400000;}
   out={users:db.users.map(pub),topics:db.topics,apps:db.apps.map(a=>({...a})),me:user?pub(user):null,online:db.users.filter(u=>pub(u).online).length};
  }else if(['register','login'].includes(path)&&req.method==='POST'){
   const nick=String(d.nick||'').trim(),pass=String(d.pass||'');
   if(!/^[A-Za-zА-Яа-яЁё0-9_]{3,24}$/.test(nick)||pass.length<5||pass.length>128)fail(400,'Ник от 3 до 24 символов, пароль от 5 до 128');
   let u=db.users.find(x=>x.nick.toLowerCase()===nick.toLowerCase());
   if(path==='register'){
    if(u)fail(409,'Этот ник уже занят');let salt=id();u={id:id(),nick,salt,hash:hash(pass,salt),joined:Date.now(),bio:'',lastSeen:Date.now(),role:'player'};db.users.push(u);
   }else{
    if(!u||u.banned)fail(401,'Неверный ник или пароль');let a=Buffer.from(u.hash,'hex'),b=Buffer.from(hash(pass,u.salt),'hex');if(a.length!==b.length||!crypto.timingSafeEqual(a,b))fail(401,'Неверный ник или пароль');
   }
   const t=crypto.randomBytes(32).toString('hex');db.sessions[t]={uid:u.id,expires:Date.now()+30*86400000};u.lastSeen=Date.now();out={token:t,user:pub(u)};
  }else if(path==='heartbeat'&&req.method==='POST'){
   auth();user.lastSeen=Date.now();session.expires=Date.now()+30*86400000;
  }else if(path==='leave'&&req.method==='POST'){
   if(user)user.lastSeen=0;
  }else if(path==='logout'&&req.method==='POST'){
   if(user){delete db.sessions[token];user.lastSeen=0;}
  }else if(path==='profile'&&req.method==='POST'){
   auth();user.bio=String(d.bio||'').trim().slice(0,300);
  }else if(path==='avatar'&&req.method==='POST'){
   auth();const avatar=String(d.avatar||'');if(avatar.length>150000||avatar&&!/^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(avatar))fail(400,'Неподходящее изображение');user.avatar=avatar;
  }else if(path==='topics'&&req.method==='POST'){
   auth();let title=String(d.title||'').trim(),body=String(d.body||'').trim(),section=String(d.section||'');if(title.length<5||title.length>100||body.length<5||body.length>5000||!sections.includes(section))fail(400,'Проверь название, текст и раздел');let t={id:id(),title,body,section,author:user.nick,time:Date.now(),replies:[]};db.topics.push(t);code=201;out={id:t.id};
  }else if(/^topics\/[a-f0-9]+\/replies$/.test(path)&&req.method==='POST'){
   auth();let t=db.topics.find(x=>x.id===path.split('/')[1]),body=String(d.body||'').trim();if(!t)fail(404,'Тема не найдена');if(body.length<2||body.length>2000)fail(400,'Ответ от 2 до 2000 символов');t.replies.push({author:user.nick,body,time:Date.now()});code=201;
  }else if(path==='applications'&&req.method==='POST'){
   auth();let title=String(d.title||'').trim(),body=String(d.body||'').trim(),type=String(d.type||'').slice(0,80);if(title.length<5||title.length>100||body.length<10||body.length>5000)fail(400,'Заполни заявку');db.apps.push({id:id(),user:user.id,author:user.nick,type,title,body,status:'На рассмотрении',time:Date.now()});code=201;
  }else if(path==='admin/unlock'&&req.method==='POST'){
   auth();const key=process.env.ADMIN_SETUP_KEY;if(!key||key.length<12)fail(503,'Администратор не настроен: нужен ADMIN_SETUP_KEY в Vercel');if(user.nick.toLowerCase()!==(process.env.ADMIN_NICK||'David_Kuertov').toLowerCase()&&user.role!=='admin')fail(403,'Недостаточно прав');const a=crypto.createHash('sha256').update(String(d.key||'')).digest(),b=crypto.createHash('sha256').update(key).digest();if(!crypto.timingSafeEqual(a,b))fail(403,'Неверный код');if(user.role!=='admin'){if(db.users.some(u=>u.role==='admin'))fail(403,'Главный администратор уже назначен');user.role='admin';}session.adminGrant=crypto.randomBytes(32).toString('hex');session.adminUntil=Date.now()+8*3600000;out={ok:true,grant:session.adminGrant,nick:user.nick};
  }else if(path==='admin/action'&&req.method==='POST'){
   admin();const action=String(d.action||'');let target=db.users.find(u=>u.id===d.userId);
   if(['ban','unban','kick','role'].includes(action)){
    if(!target)fail(404,'Игрок не найден');if(target.id===user.id)fail(400,'Нельзя изменять свой аккаунт');if(target.role==='admin'&&['ban','kick'].includes(action))fail(403,'Нельзя забанить администратора');
    if(action==='ban'||action==='kick'){if(action==='ban')target.banned=true;target.lastSeen=0;for(const [t,s] of Object.entries(db.sessions))if(s.uid===target.id)delete db.sessions[t];}
    if(action==='unban')target.banned=false;
    if(action==='role'){if(target.nick.toLowerCase()===(process.env.ADMIN_NICK||'David_Kuertov').toLowerCase())fail(403,'Нельзя изменить роль владельца');if(!['player','admin'].includes(d.role))fail(400,'Неизвестная роль');target.role=d.role;}
   }else if(action==='deleteTopic'){let i=db.topics.findIndex(t=>t.id===d.topicId);if(i<0)fail(404,'Тема не найдена');db.topics.splice(i,1);
   }else if(action==='deleteReply'){let t=db.topics.find(t=>t.id===d.topicId);if(!t||!Number.isInteger(d.index)||d.index<0||d.index>=t.replies.length)fail(404,'Ответ не найден');t.replies.splice(d.index,1);
   }else if(action==='application'){let a=db.apps.find(a=>a.id===d.appId);if(!a)fail(404,'Заявка не найдена');if(!['На рассмотрении','Одобрено','Отклонено'].includes(d.status))fail(400,'Неизвестный статус');a.status=d.status;
   }else if(action==='replyApplication'){let a=db.apps.find(a=>a.id===d.appId);if(!a)fail(404,'Заявка не найдена');let msg=String(d.message||'').trim();if(msg.length<2||msg.length>3000)fail(400,'Ответ от 2 до 3000 символов');a.adminReply=msg;a.answeredBy=user.nick;a.answeredAt=Date.now();
   }else fail(400,'Неизвестное действие');
  }else fail(404,'Неизвестный запрос');
  await client.query('UPDATE rp196_store SET state=$1::jsonb WHERE id=1',[JSON.stringify(db)]);
  await client.query('COMMIT');return send(code,out);
 }catch(e){await client.query('ROLLBACK').catch(()=>{});if(e.status)return send(e.status,{error:e.message});console.error(e);return send(500,{error:'Ошибка базы данных или сервера'});}finally{client.release();}
};
