import re,sqlite3
from pathlib import Path
s=Path('worker/index.js').read_text()
queries=re.findall(r"prepare\('([^']+)'\)",s)
save=next(q for q in queries if 'INSERT INTO oauth_records(key,payload,expires_at) SELECT' in q)
consume=next(q for q in queries if 'RETURNING payload' in q)
db=sqlite3.connect(':memory:')
for sql in Path('drizzle/0000_google_oauth.sql').read_text().split('--> statement-breakpoint'):
 db.executescript(sql)
db.execute('INSERT INTO oauth_generations VALUES (?,?)',('u',0))
assert db.execute(save,('connection:u','ENCRYPTED', 'u',0,'u',0)).rowcount==1
assert db.execute(save,('connection:u','UPDATED', 'u',0,'u',0)).rowcount==1
db.execute('UPDATE oauth_generations SET generation=1 WHERE user_id=?',('u',))
assert db.execute(save,('connection:u','STALE', 'u',0,'u',0)).rowcount==0
assert db.execute('SELECT payload FROM oauth_records WHERE key=?',('connection:u',)).fetchone()[0]=='UPDATED'
db.execute('INSERT INTO oauth_records VALUES(?,?,?)',('attempt:u:x','ENCRYPTED_ATTEMPT',1000))
assert db.execute(consume,('attempt:u:x',100)).fetchone()[0]=='ENCRYPTED_ATTEMPT'
assert db.execute(consume,('attempt:u:x',100)).fetchone() is None
print('PASS: actual SQLite schema, atomic state consumption, guarded upsert and disconnect generation isolation')
