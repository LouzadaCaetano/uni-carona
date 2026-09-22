from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse
from http.cookies import SimpleCookie
import json, sqlite3, os, re, math, datetime, secrets, hashlib, hmac

BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(BASE, 'static')
DB = os.path.join(BASE, 'unicarona.db')

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def now(): return datetime.datetime.now().isoformat(timespec='seconds')

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 120000).hex()
    return f'{salt}${digest}'

def check_password(password, stored):
    try:
        salt, old = stored.split('$', 1)
        new = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 120000).hex()
        return hmac.compare_digest(old, new)
    except Exception:
        return False

def init_db():
    conn = db(); cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      photo TEXT,
      is_admin INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions(
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS driver_profiles(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER UNIQUE NOT NULL,
      vehicle_model TEXT NOT NULL,
      plate TEXT NOT NULL,
      cnh TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
      reviewed_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS rides(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      passenger_user_id INTEGER NOT NULL,
      origin_label TEXT NOT NULL,
      destination_label TEXT NOT NULL,
      origin_lat REAL, origin_lng REAL,
      destination_lat REAL, destination_lng REAL,
      distance_km REAL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','cancelled')),
      driver_user_id INTEGER,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(passenger_user_id) REFERENCES users(id),
      FOREIGN KEY(driver_user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS ride_rejections(
      ride_id INTEGER NOT NULL,
      driver_user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY(ride_id, driver_user_id),
      FOREIGN KEY(ride_id) REFERENCES rides(id) ON DELETE CASCADE,
      FOREIGN KEY(driver_user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)
    admin_email='admin@unicarona.local'
    if not cur.execute('SELECT 1 FROM users WHERE email=?',(admin_email,)).fetchone():
        cur.execute('INSERT INTO users(name,email,password_hash,is_admin,created_at) VALUES(?,?,?,?,?)',
                    ('Administrador UniCarona', admin_email, hash_password('admin123'), 1, now()))
    conn.commit(); conn.close()

def haversine(lat1, lon1, lat2, lon2):
    if None in (lat1, lon1, lat2, lon2): return None
    R=6371.0
    p1,p2=math.radians(lat1),math.radians(lat2)
    dp=math.radians(lat2-lat1); dl=math.radians(lon2-lon1)
    a=math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return round(2*R*math.asin(math.sqrt(a)),2)

def public_user(row):
    return {'id':row['id'],'name':row['name'],'email':row['email'],'photo':row['photo'],'is_admin':bool(row['is_admin']),'created_at':row['created_at']}

class Handler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        clean=urlparse(path).path
        if clean=='/': clean='/index.html'
        return os.path.join(STATIC, clean.lstrip('/'))

    def send_json(self,obj,status=200,cookie=None):
        data=json.dumps(obj,ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length',str(len(data)))
        if cookie: self.send_header('Set-Cookie',cookie)
        self.end_headers(); self.wfile.write(data)

    def read_json(self):
        try:
            n=int(self.headers.get('Content-Length','0'))
            return json.loads(self.rfile.read(n) or b'{}')
        except Exception: return {}

    def session_token(self):
        c=SimpleCookie(); c.load(self.headers.get('Cookie',''))
        return c.get('session').value if c.get('session') else None

    def current_user(self):
        tok=self.session_token()
        if not tok:return None
        conn=db(); row=conn.execute('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=?',(tok,)).fetchone(); conn.close()
        return row

    def require_user(self,admin=False):
        u=self.current_user()
        if not u:
            self.send_json({'error':'Faça login para continuar.'},401); return None
        if admin and not u['is_admin']:
            self.send_json({'error':'Acesso restrito ao administrador.'},403); return None
        return u

    def do_GET(self):
        path=urlparse(self.path).path
        if path=='/api/health': return self.send_json({'ok':True})
        if path=='/api/me':
            u=self.require_user();
            if not u:return
            conn=db(); drv=conn.execute('SELECT * FROM driver_profiles WHERE user_id=?',(u['id'],)).fetchone(); conn.close()
            out=public_user(u); out['driver_profile']=dict(drv) if drv else None
            return self.send_json(out)
        if path=='/api/my/rides':
            u=self.require_user();
            if not u:return
            conn=db(); rows=conn.execute('''SELECT r.*, d.name driver_name, d.email driver_email, dp.vehicle_model, dp.plate
              FROM rides r LEFT JOIN users d ON d.id=r.driver_user_id
              LEFT JOIN driver_profiles dp ON dp.user_id=r.driver_user_id
              WHERE r.passenger_user_id=? ORDER BY r.id DESC''',(u['id'],)).fetchall(); conn.close()
            return self.send_json([dict(r) for r in rows])
        if path=='/api/driver/rides':
            u=self.require_user();
            if not u:return
            conn=db(); drv=conn.execute("SELECT * FROM driver_profiles WHERE user_id=? AND status='approved'",(u['id'],)).fetchone()
            if not drv:
                conn.close(); return self.send_json({'error':'Seu cadastro de motorista ainda não está aprovado.'},403)
            rows=conn.execute('''SELECT r.*, p.name passenger_name, p.email passenger_email
              FROM rides r JOIN users p ON p.id=r.passenger_user_id
              LEFT JOIN ride_rejections rr ON rr.ride_id=r.id AND rr.driver_user_id=?
              WHERE (r.status='pending' AND rr.ride_id IS NULL AND r.passenger_user_id<>?) OR r.driver_user_id=?
              ORDER BY r.id DESC''',(u['id'],u['id'],u['id'])).fetchall(); conn.close()
            return self.send_json([dict(r) for r in rows])
        if path=='/api/admin/users':
            u=self.require_user(admin=True)
            if not u:return
            conn=db(); rows=conn.execute('''SELECT u.id,u.name,u.email,u.is_admin,u.created_at,dp.status driver_status,dp.vehicle_model,dp.plate,dp.cnh
              FROM users u LEFT JOIN driver_profiles dp ON dp.user_id=u.id ORDER BY u.id DESC''').fetchall(); conn.close()
            return self.send_json([dict(r) for r in rows])
        if path=='/api/admin/drivers':
            u=self.require_user(admin=True)
            if not u:return
            conn=db(); rows=conn.execute('SELECT dp.*,u.name,u.email FROM driver_profiles dp JOIN users u ON u.id=dp.user_id ORDER BY dp.id DESC').fetchall(); conn.close()
            return self.send_json([dict(r) for r in rows])
        if path=='/api/admin/rides':
            u=self.require_user(admin=True)
            if not u:return
            conn=db(); rows=conn.execute('''SELECT r.*,p.name passenger_name,d.name driver_name
              FROM rides r JOIN users p ON p.id=r.passenger_user_id LEFT JOIN users d ON d.id=r.driver_user_id ORDER BY r.id DESC''').fetchall(); conn.close()
            return self.send_json([dict(r) for r in rows])
        return super().do_GET()

    def do_POST(self):
        path=urlparse(self.path).path; data=self.read_json()
        if path=='/api/register':
            name=(data.get('name') or '').strip(); email=(data.get('email') or '').strip().lower(); password=data.get('password') or ''
            if len(name)<2 or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$',email) or len(password)<6:
                return self.send_json({'error':'Informe nome, e-mail válido e senha com pelo menos 6 caracteres.'},400)
            try:
                conn=db(); cur=conn.execute('INSERT INTO users(name,email,password_hash,is_admin,created_at) VALUES(?,?,?,?,?)',(name,email,hash_password(password),0,now())); conn.commit(); uid=cur.lastrowid; conn.close()
                tok=secrets.token_urlsafe(32); conn=db(); conn.execute('INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)',(tok,uid,now())); conn.commit(); conn.close()
                return self.send_json({'message':'Cadastro criado com sucesso.'},201,f'session={tok}; Path=/; HttpOnly; SameSite=Lax')
            except sqlite3.IntegrityError:
                return self.send_json({'error':'Este e-mail já está cadastrado.'},409)
        if path=='/api/login':
            email=(data.get('email') or '').strip().lower(); password=data.get('password') or ''
            conn=db(); row=conn.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone(); conn.close()
            if not row or not check_password(password,row['password_hash']):
                return self.send_json({'error':'E-mail ou senha inválidos.'},401)
            tok=secrets.token_urlsafe(32); conn=db(); conn.execute('INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)',(tok,row['id'],now())); conn.commit(); conn.close()
            return self.send_json({'message':'Login realizado.'},200,f'session={tok}; Path=/; HttpOnly; SameSite=Lax')
        if path=='/api/logout':
            tok=self.session_token()
            if tok:
                conn=db(); conn.execute('DELETE FROM sessions WHERE token=?',(tok,)); conn.commit(); conn.close()
            return self.send_json({'message':'Sessão encerrada.'},200,'session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax')
        if path=='/api/driver/apply':
            u=self.require_user();
            if not u:return
            vehicle=(data.get('vehicle_model') or '').strip(); plate=(data.get('plate') or '').strip().upper(); cnh=re.sub(r'\D','',(data.get('cnh') or ''))
            if not vehicle or not plate or not re.match(r'^\d{9,11}$',cnh):
                return self.send_json({'error':'Informe veículo, placa e CNH com 9 a 11 dígitos.'},400)
            conn=db(); existing=conn.execute('SELECT 1 FROM driver_profiles WHERE user_id=?',(u['id'],)).fetchone()
            if existing:
                conn.close(); return self.send_json({'error':'Já existe uma solicitação de motorista para esta conta.'},409)
            conn.execute('INSERT INTO driver_profiles(user_id,vehicle_model,plate,cnh,status,created_at) VALUES(?,?,?,?,?,?)',(u['id'],vehicle,plate,cnh,'pending',now())); conn.commit(); conn.close()
            return self.send_json({'message':'Solicitação enviada. Aguarde a análise manual do administrador.'},201)
        if path=='/api/rides':
            u=self.require_user();
            if not u:return
            origin=(data.get('origin_label') or '').strip(); dest=(data.get('destination_label') or '').strip()
            if not origin or not dest:return self.send_json({'error':'Informe origem e destino.'},400)
            def num(k):
                try:return float(data[k]) if data.get(k) not in ('',None) else None
                except:return None
            olat,olng,dlat,dlng=map(num,('origin_lat','origin_lng','destination_lat','destination_lng'))
            dist=haversine(olat,olng,dlat,dlng)
            conn=db(); cur=conn.execute('''INSERT INTO rides(passenger_user_id,origin_label,destination_label,origin_lat,origin_lng,destination_lat,destination_lng,distance_km,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)''',(u['id'],origin,dest,olat,olng,dlat,dlng,dist,'pending',now(),now())); conn.commit(); rid=cur.lastrowid; conn.close()
            return self.send_json({'id':rid,'distance_km':dist,'message':'Solicitação criada. Motoristas aprovados já podem visualizá-la.'},201)
        m=re.match(r'^/api/driver/rides/(\d+)/(accept|reject)$',path)
        if m:
            u=self.require_user();
            if not u:return
            conn=db(); drv=conn.execute("SELECT 1 FROM driver_profiles WHERE user_id=? AND status='approved'",(u['id'],)).fetchone()
            if not drv:
                conn.close(); return self.send_json({'error':'Seu perfil de motorista precisa estar aprovado.'},403)
            rid=int(m.group(1)); action=m.group(2)
            if action=='accept':
                cur=conn.execute("UPDATE rides SET status='accepted',driver_user_id=?,updated_at=? WHERE id=? AND status='pending' AND passenger_user_id<>?",(u['id'],now(),rid,u['id'])); conn.commit(); conn.close()
                if cur.rowcount==0:return self.send_json({'error':'Esta solicitação não está mais disponível.'},409)
                return self.send_json({'message':'Carona aceita. O passageiro já pode ver seus dados.'})
            try:
                conn.execute('INSERT INTO ride_rejections(ride_id,driver_user_id,created_at) VALUES(?,?,?)',(rid,u['id'],now())); conn.commit()
            except sqlite3.IntegrityError: pass
            conn.close(); return self.send_json({'message':'Solicitação recusada para o seu perfil. Ela continua disponível para outros motoristas.'})
        m=re.match(r'^/api/admin/drivers/(\d+)/(approve|reject)$',path)
        if m:
            u=self.require_user(admin=True)
            if not u:return
            did=int(m.group(1)); status='approved' if m.group(2)=='approve' else 'rejected'
            conn=db(); cur=conn.execute('UPDATE driver_profiles SET status=?,reviewed_at=? WHERE id=?',(status,now(),did)); conn.commit(); conn.close()
            if cur.rowcount==0:return self.send_json({'error':'Solicitação não encontrada.'},404)
            return self.send_json({'message':'Cadastro de motorista '+('aprovado.' if status=='approved' else 'rejeitado.')})
        return self.send_json({'error':'Rota não encontrada.'},404)

    def log_message(self, fmt,*args): print('[HTTP]',fmt%args)

if __name__=='__main__':
    init_db(); port=int(os.environ.get('PORT','8080'))
    print(f'UniCarona disponível em http://localhost:{port}')
    print('ADM: admin@unicarona.local | senha: admin123')
    ThreadingHTTPServer(('0.0.0.0',port),Handler).serve_forever()
