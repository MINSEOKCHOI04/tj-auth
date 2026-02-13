const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const SESSION_TTL_MS = 60 * 60 * 1000; // 1시간

// email -> Map(sessionId -> { profileId, ip, last })
const activeSessions = new Map();

const nowKR = () => new Date().toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' });

const clientIP = (req) => {
  const xff = req.headers['x-forwarded-for'] || '';
  return (xff.split(',')[0] || '').trim() || req.connection.remoteAddress || '';
};

// 만료 세션 정리
function pruneExpired(email) {
  const sessions = activeSessions.get(email);
  if (!sessions) return;

  for (const [sid, s] of sessions.entries()) {
    if (Date.now() - s.last > SESSION_TTL_MS) {
      sessions.delete(sid);
    }
  }

  if (sessions.size === 0) {
    activeSessions.delete(email);
  }
}

app.get('/', (_, res) => res.send('🚀 인증 서버 실행 중'));

// ✅ 로그인 (동시 로그인 허용)
app.all('/auth', (req, res) => {
  const usersPath = path.join(__dirname, 'users.json');
  const users = JSON.parse(fs.readFileSync(usersPath, 'utf-8'));

  const q = req.method === 'GET' ? req.query : req.body;
  const email = String(q.email || '').trim();
  const code = String(q.code || '').trim();
  const profileId = String(q.profileId || '').trim();
  const ip = clientIP(req);
  const time = nowKR();

  if (!email || !code || !profileId)
    return res.json({ ok: false, msg: 'email, code, profileId 필요' });

  if (!users[email] || users[email] !== code) {
    console.log(`[실패] 🔴 ${time} | ${email} | IP:${ip}`);
    return res.json({ ok: false, msg: '아이디 또는 비밀번호 오류' });
  }

  pruneExpired(email);

  const sessionId = 'sess_' + crypto.randomBytes(8).toString('hex');

  if (!activeSessions.has(email)) {
    activeSessions.set(email, new Map());
  }

  activeSessions.get(email).set(sessionId, {
    profileId,
    ip,
    last: Date.now()
  });

  console.log(`[로그인] 🟢 ${time} | ${email} | 프로필:${profileId} | 세션:${sessionId}`);

  return res.json({ ok: true, sessionId, profileId, ttlMs: SESSION_TTL_MS });
});

// ✅ 세션 확인
app.get('/check', (req, res) => {
  const email = String(req.query.email || '').trim();
  const profileId = String(req.query.profileId || '').trim();
  const sessionId = String(req.query.sessionId || '').trim();

  if (!email || !profileId || !sessionId)
    return res.json({ ok: false, msg: 'email, profileId, sessionId 필요' });

  pruneExpired(email);

  const sessions = activeSessions.get(email);
  if (!sessions || !sessions.has(sessionId))
    return res.json({ ok: false, expired: true });

  const cur = sessions.get(sessionId);

  const valid = Date.now() - cur.last <= SESSION_TTL_MS;
  if (!valid) {
    sessions.delete(sessionId);
    return res.json({ ok: false, expired: true });
  }

  return res.json({
    ok: true,
    sessionId,
    expiresInMs: SESSION_TTL_MS - (Date.now() - cur.last)
  });
});

// ✅ 하트비트
app.post('/touch', (req, res) => {
  const { email, sessionId } = req.body || {};
  if (!email || !sessionId)
    return res.json({ ok: false, msg: 'email, sessionId 필요' });

  const sessions = activeSessions.get(email);
  if (!sessions || !sessions.has(sessionId))
    return res.json({ ok: false, expired: true });

  sessions.get(sessionId).last = Date.now();
  return res.json({ ok: true });
});

// ✅ 로그아웃 (해당 세션만 종료)
app.all('/logout', (req, res) => {
  const q = req.method === 'GET' ? req.query : req.body;
  const email = String(q.email || '').trim();
  const sessionId = String(q.sessionId || '').trim();

  if (!email || !sessionId)
    return res.json({ ok: false, msg: 'email, sessionId 필요' });

  const sessions = activeSessions.get(email);
  if (sessions && sessions.has(sessionId)) {
    sessions.delete(sessionId);
    console.log(`[로그아웃] 🔓 ${nowKR()} | ${email} | 세션:${sessionId}`);
    return res.json({ ok: true });
  }

  return res.json({ ok: false, msg: '세션 없음' });
});

app.listen(PORT, () =>
  console.log(`✅ 서버가 포트 ${PORT}에서 실행 중`)
);