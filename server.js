const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'database.json');

const JWT_SECRET = process.env.JWT_SECRET || process.env.SECRET_KEY || 'CHANGE_ME_RAILWAY_JWT_SECRET_2026';
const DATA_SECRET_PIN = process.env.DATA_SECRET_PIN || 'CHANGE_ME_PIN';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'CHANGE_ME_ADMIN_PASSWORD';
const USER_USERNAME = process.env.USER_USERNAME || '';
const USER_PASSWORD = process.env.USER_PASSWORD || '';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const COOKIE_NAME = 'admin_session';
const isProd = process.env.NODE_ENV === 'production';

const defaultDb = {
  config: { active: true },
  app: { name: 'Portal App', title: 'Secure Login', description: 'Apne account me login karein', logoUrl: '', media: [] },
  users: [],
  logs: [],
  audit: []
};
function loadDb(){
  try { if(fs.existsSync(DB_FILE)) return { ...defaultDb, ...JSON.parse(fs.readFileSync(DB_FILE,'utf8')) }; } catch(e) { console.error('Database load failed'); }
  return JSON.parse(JSON.stringify(defaultDb));
}
let db = loadDb();
let persistTimer;
function persist(){ clearTimeout(persistTimer); persistTimer=setTimeout(()=>{ try { fs.writeFileSync(DB_FILE, JSON.stringify(db,null,2), 'utf8'); } catch(e){ console.error('Database save failed'); } }, 100); }

const originCheck = (origin, cb) => {
  if (!origin || ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
  return cb(new Error('CORS origin denied'));
};
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: originCheck, credentials: true, methods: ['GET','POST','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json({limit:'2mb'}));
app.use(cookieParser());
app.use('/uploads', express.static(UPLOAD_DIR, { fallthrough:false, maxAge:'1h' }));

const upload = multer({
  storage: multer.diskStorage({ destination: UPLOAD_DIR, filename:(req,file,cb)=>cb(null, crypto.randomUUID()+path.extname(file.originalname).toLowerCase()) }),
  limits:{ fileSize: 25*1024*1024 },
  fileFilter:(req,file,cb)=>{
    const ok=/^image\/(png|jpeg|webp|gif)$/.test(file.mimetype) || /^video\/(mp4|webm|quicktime)$/.test(file.mimetype);
    cb(ok?null:new Error('Unsupported media type'), ok);
  }
});

function hashPassword(password){ return new Promise((resolve,reject)=>crypto.scrypt(password, crypto.randomBytes(16), 64, (err,key)=>{ if(err)return reject(err); resolve(key.toString('hex')); }); }); }
function verifyPassword(password, record){ return new Promise(resolve=>{ if(!record?.salt || !record?.passwordHash)return resolve(false); crypto.scrypt(password, Buffer.from(record.salt,'hex'),64,(err,key)=>{ if(err)return resolve(false); const a=Buffer.from(record.passwordHash,'hex'), b=Buffer.from(key.toString('hex'),'hex'); resolve(a.length===b.length && crypto.timingSafeEqual(a,b)); }); }); }
function makeUserRecord(username, password){ const salt=crypto.randomBytes(16); return new Promise((resolve,reject)=>crypto.scrypt(password,salt,64,(err,key)=>{if(err)return reject(err); resolve({id:crypto.randomUUID(),username,email:username, passwordHash:key.toString('hex'),salt:salt.toString('hex'),status:'ACTIVE',createdAt:new Date().toISOString(),lastLogin:null,lastAction:'Account created',lastActionAt:new Date().toISOString(),profilePictureUrl:''});})); }
function publicUser(u){ if(!u)return null; return {id:u.id,username:u.username,email:u.email,status:u.status||'ACTIVE',createdAt:u.createdAt,lastLogin:u.lastLogin,lastAction:u.lastAction,lastActionAt:u.lastActionAt,profilePictureUrl:u.profilePictureUrl||''}; }
function signAdmin(){ return jwt.sign({role:'admin',sub:ADMIN_USERNAME},JWT_SECRET,{expiresIn:'5h'}); }
function adminAuth(req,res,next){
  try{
    const token=req.cookies[COOKIE_NAME] || (req.headers.authorization||'').replace(/^Bearer\s+/i,'');
    if(!token) return res.status(401).json({error:'Admin session required.'});
    req.admin=jwt.verify(token,JWT_SECRET); if(req.admin.role!=='admin')throw new Error(); next();
  }catch(e){ return res.status(401).json({error:'Admin session expired or invalid.'}); }
}
function pinAuth(req,res,next){ if(req.body?.dataPin!==DATA_SECRET_PIN || DATA_SECRET_PIN.startsWith('CHANGE_ME')) return res.status(403).json({error:'Security PIN is incorrect or not configured.'}); next(); }
function addAudit(action,userId,meta={}){ db.audit.unshift({id:crypto.randomUUID(),action,userId:userId||null,time:new Date().toISOString(),meta:{...meta}}); db.audit=db.audit.slice(0,500); persist(); }
function addLog(username,status){ db.logs.unshift({username,timestamp:new Date().toISOString(),status}); db.logs=db.logs.slice(0,500); persist(); }

app.get('/',(req,res)=>res.json({ok:true,service:'Secure Admin/Login Backend'}));
app.get('/api/health',(req,res)=>res.json({ok:true,time:new Date().toISOString()}));
app.get('/api/config',(req,res)=>res.json({active:db.config.active!==false}));
app.get('/api/app-config',(req,res)=>res.json({app:db.app}));
app.get('/api/app-settings',(req,res)=>res.json(db.app));

app.post('/api/login', async (req,res)=>{
  if(db.config.active===false) return res.status(503).json({error:'Login is currently OFF.'});
  const username=String(req.body?.username||req.body?.email||'').trim(); const password=String(req.body?.password||'');
  if(!username || !password) return res.status(400).json({error:'Username and password are required.'});
  let user=db.users.find(u=>u.username.toLowerCase()===username.toLowerCase());
  if(!user && USER_USERNAME && username===USER_USERNAME){
    user=await makeUserRecord(username,USER_PASSWORD); db.users.push(user); persist();
  }
  if(!user){ addLog(username,'LOGIN_FAILED'); return res.status(401).json({error:'Invalid username or password.'}); }
  const ok=await verifyPassword(password,user);
  if(!ok){ addLog(username,'LOGIN_FAILED'); user.lastAction='Failed login'; user.lastActionAt=new Date().toISOString(); persist(); return res.status(401).json({error:'Invalid username or password.'}); }
  user.lastLogin=new Date().toISOString(); user.lastAction='Successful login'; user.lastActionAt=new Date().toISOString(); addLog(username,'LOGIN_SUCCESS');
  res.json({success:true,message:'Login successful',user:{username:user.username,email:user.email,status:user.status}});
});

app.post('/api/admin/login',(req,res)=>{
  const username=String(req.body?.username||''); const password=String(req.body?.password||'');
  if(username!==ADMIN_USERNAME || ADMIN_PASSWORD.startsWith('CHANGE_ME') || password!==ADMIN_PASSWORD) return res.status(401).json({error:'Incorrect Username or Password.'});
  const token=signAdmin(); res.cookie(COOKIE_NAME,token,{httpOnly:true,secure:isProd,sameSite:isProd?'none':'lax',maxAge:5*60*60*1000}); res.json({success:true});
});
app.post('/api/admin/logout',adminAuth,(req,res)=>{res.clearCookie(COOKIE_NAME,{httpOnly:true,secure:isProd,sameSite:isProd?'none':'lax'});res.json({success:true});});
app.get('/api/admin/me',adminAuth,(req,res)=>res.json({authenticated:true,username:req.admin.sub}));

app.post('/api/config',adminAuth,(req,res)=>{db.config.active=req.body?.active!==false;persist();res.json({success:true,active:db.config.active});});
app.get('/api/logs',adminAuth,(req,res)=>res.json(db.logs.map(x=>({username:x.username,timestamp:x.timestamp,status:x.status}))));
app.delete('/api/logs',adminAuth,(req,res)=>{db.logs=[];persist();res.json({success:true});});
app.post('/api/app-config',adminAuth,(req,res)=>{const {name,title,description}=req.body||{};if(typeof name==='string')db.app.name=name;if(typeof title==='string')db.app.title=title;if(typeof description==='string')db.app.description=description;persist();res.json({success:true,app:db.app});});
app.post('/api/app-media',adminAuth,upload.single('file'),(req,res)=>{if(!req.file)return res.status(400).json({error:'No file uploaded.'});const url=`/uploads/${req.file.filename}`;const kind=String(req.body?.kind||'media');if(kind==='logo')db.app.logoUrl=url;else db.app.media.push({id:crypto.randomUUID(),kind,url,name:req.file.originalname,time:new Date().toISOString()});persist();res.json({success:true,url,kind});});

app.post('/api/admin/user-data',adminAuth,pinAuth,(req,res)=>res.json({success:true,users:db.users.map(publicUser)}));
app.post('/api/admin/get-users',adminAuth,pinAuth,(req,res)=>res.json({success:true,users:db.users.map(publicUser)}));
app.post('/api/admin/user-data/:id',adminAuth,pinAuth,(req,res)=>{const u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'User not found.'});res.json({success:true,user:publicUser(u)});});
app.post('/api/admin/user-status/:id',adminAuth,(req,res)=>{const u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'User not found.'});u.status=req.body?.status==='DISABLED'?'DISABLED':'ACTIVE';u.lastAction='Admin changed account status';u.lastActionAt=new Date().toISOString();addAudit('user_status',u.id,{status:u.status});persist();res.json({success:true,user:publicUser(u)});});
app.post('/api/admin/reset-user-password/:id',adminAuth,(req,res)=>{const u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'User not found.'});const newPassword=String(req.body?.newPassword||'');if(newPassword.length<8)return res.status(400).json({error:'New password must be at least 8 characters.'});crypto.randomBytes(16,(err,salt)=>{if(err)return res.status(500).json({error:'Password reset failed.'});crypto.scrypt(newPassword,salt,64,(e,key)=>{if(e)return res.status(500).json({error:'Password reset failed.'});u.salt=salt.toString('hex');u.passwordHash=key.toString('hex');u.lastAction='Admin reset password';u.lastActionAt=new Date().toISOString();addAudit('password_reset',u.id);persist();res.json({success:true,message:'Password reset. Old password is not readable.'});});});});
app.post('/api/admin/user-profile-picture/:id',adminAuth,upload.single('file'),(req,res)=>{const u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'User not found.'});if(!req.file)return res.status(400).json({error:'No image uploaded.'});u.profilePictureUrl=`/uploads/${req.file.filename}`;u.lastAction='Admin updated profile picture';u.lastActionAt=new Date().toISOString();addAudit('profile_picture',u.id);persist();res.json({success:true,url:u.profilePictureUrl});});
app.get('/api/admin/user-audit',adminAuth,(req,res)=>res.json({audit:db.audit.map(x=>({id:x.id,action:x.action,userId:x.userId,time:x.time,meta:x.meta}))}));
app.delete('/api/admin/delete-user/:id',adminAuth,(req,res)=>{const before=db.users.length;db.users=db.users.filter(x=>x.id!==req.params.id);if(before===db.users.length)return res.status(404).json({error:'User not found.'});addAudit('user_deleted',req.params.id);persist();res.json({success:true});});

app.use((err,req,res,next)=>{console.error('Request error:',err.message);res.status(400).json({error:err.message||'Request failed'});});
app.listen(PORT,()=>console.log(`Secure backend listening on ${PORT}`));
